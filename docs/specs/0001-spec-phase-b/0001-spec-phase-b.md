# 0001 Spec: Phase B (auth, owner-only authorization, MCP)

Status: draft, 2026-10-07.

## Goal

Make the relay safe to carry members' real notes and reachable from outside
the cluster.

1. Every connection is authenticated as an SCN member's DID.
2. A member can open only documents in their own vaults.
3. A built-in MCP service lets an MCP client read and edit a member's notes,
   acting as that member.

The rule for all three: access works while you are an SCN member and stops
when you are not.

## Non-goals

- Sharing a vault between members. Each vault has one owner.
- ATProto service-auth verification. The verifier seam keeps room for it.
- Deleting notes through MCP.
- Renaming or deleting a vault. Vaults are created and listed only.
- A server-side markdown exporter. The `.md` files are written by the plugin
  on each device.
- Removing a deleted note's stored document. See Z4.
- End-to-end encryption. The relay can read every document.
- Compaction of document history.

## Current state (v0.1.2)

- samod 0.15 over axum 0.8, storing through sqlx 0.9 to one Postgres
  key/value table
  (`src/storage.rs`).
- Websocket at `/` and `/sync`, liveness at `/health` (`src/main.rs:82-84`).
- No authentication. `build_verifier` returns `AllowAll` or refuses to start
  (`src/main.rs:121-130`). `sync()` calls `verify(None)` and never reads the
  URL (`src/main.rs:146`). It accepts the socket with no expected peer ID
  (`src/main.rs:161`).
- No authorization. samod's default announce policy offers every loaded
  document to every peer.
- No documents. The relay has never held content, so Phase B starts on an
  empty `storage` table and there is nothing to migrate or assign an owner.

## What samod does and does not enforce

Read from samod and samod-core 0.15.0 source.

- `AnnouncePolicy::should_announce(DocumentId, PeerId)` is samod's only
  policy hook. It decides whether the relay offers a document first.
- It does not gate inbound messages. A peer that sends a `request` or `sync`
  for a document ID gets the document and can write to it, whatever the
  policy says (samod-core `src/actors/document/phase/ready.rs:29-66`).
- A message for an unknown document ID creates that document on the relay
  (samod-core `src/actors/hub/state.rs:731-744`). There is no hook for it.
- The peer ID is whatever the client declares in its handshake, unless the
  transport is given an expected one.
- samod has no public call to close one connection.

Authorization therefore cannot live inside samod. It lives in a filter on
each connection's transport, described below.

## Dependency changes

| Crate | Change | Why |
|---|---|---|
| `automerge` | add, matching samod's version | Text edits and folder document reads in the MCP tools |
| `rmcp` | add, 3.x, features `server`, `macros`, `transport-streamable-http-server` | MCP Streamable HTTP server as a tower service |
| `jsonwebtoken` | add | Verify RS256 access tokens |
| `reqwest` | add, rustls | Fetch the issuer's JWKS |
| `minicbor` | add | Read the sync protocol's message envelope |
| `serde`, `serde_json` | add | Tokens, endpoints, tool arguments |

rmcp needs Rust 1.88. `rust-version` in `Cargo.toml` is already 1.94, set by
sqlx 0.9.

## Document schema

Settled in the scn-obsidian plugin spec, sections D1 to D5, and repeated
here.

- A folder document is `{"@patchwork": {"type": "folder"}, "title", "docs"}`.
  `docs` is a list of entries `{name, type, url}`.
- A note document is `{"@patchwork": {"type": "file"}, "name", "extension":
  "md", "mimeType": "text/markdown", "content"}`. `content` is an Automerge
  text object holding the file's text exactly.
- String values are Automerge text objects, which is how the JS client
  writes a string. The relay writes them that way and reads either a text
  object or a scalar string.
- An entry's `type` is `folder`, or the file's extension. The relay acts on
  `folder` and `md` and ignores every other entry: it does not walk it,
  list it, search it or admit it to a vault's reachable set.
- A name is one path segment: not empty, not `.` or `..`, no `/`, no
  leading dot, stored in NFC. `create_note` refuses any other name, and
  refuses a name that collides with an existing entry after NFC and case
  folding.
- **Path resolution with duplicate names.** When a folder holds two entries
  whose names collide, the entry whose `url` sorts lowest as a string is
  the one the path refers to. Clients rename the others; see the plugin
  spec, T4.
- Vault creation writes a root folder document with `title` set to the
  vault's name and an empty `docs` list.
- `create_note` writes the note document first, then appends the entry.
  `edit_note` and `append_note` splice `content` and never replace it.
- Text positions are computed in whatever unit the relay's Automerge build
  uses, by the relay, on the document it holds. No position crosses the
  wire.

## Authentication

### A1. Corliss token verifier

`CorlissVerifier` implements the existing `DidVerifier` trait
(`src/auth.rs:53`).

- Fetch the issuer's JWKS at startup and cache it. On a token whose `kid` is
  not in the cache, refetch once, with a floor on how often that can happen.
- Accept RS256 only.
- Check signature, `iss`, `exp`, and `aud`. The expected audience is passed
  in by the caller, because sync and MCP have different audiences.
- Return `Did(sub)` and the expiry time. The trait's return type grows to
  carry the expiry.
- Reject a `sub` that is not a DID.

`build_verifier` selects `CorlissVerifier` when `REQUIRE_AUTH` is true. If
the issuer or audience settings are missing, the relay refuses to start. With
`REQUIRE_AUTH=false` it keeps today's `AllowAll` behaviour for local work,
and the filter below is not installed.

A second verifier for ATProto service auth can be added behind the same
trait later. Everything past the verifier sees only a DID.

### A2. Token in the URL for sync

Browser and mobile websockets cannot set an `Authorization` header. The
client connects to `wss://<sync host>/?access_token=<jwt>`.

- `sync()` reads `access_token` from the query string and passes it to
  `verify()`.
- A missing, expired, wrong-audience or otherwise invalid token gets `401`
  before the upgrade. The response body does not say why.
- The token and the query string are never logged.

### A3. Close at token expiry

The transport filter ends the connection when the token's `exp` passes. The
client reconnects with a fresh token. A member removed from the network
loses sync within one token lifetime.

## Authorization

### Z1. One function

```rust
async fn may_open(&self, did: &Did, doc: &DocumentId) -> bool
```

Every check goes through it: inbound sync frames, outbound sync frames, and
every MCP tool. It answers true when either holds:

- the document is in the reachable set of a vault owned by `did`, or
- `doc_creators` records `did` as the document's creator and the document is
  not in any vault's reachable set.

The second case covers three states: a note created and not yet linked into
a folder document, a note part way through a move between folders, and a note
whose entry was deleted. In all three the creator can still sync the
document, and no path leads to it.

Both cases are answered from memory (Z2, Z4). `may_open` makes no database
call.

When sharing arrives, only the backing of this function changes.

### Z2. Ownership records

Two tables beside `storage`, created at startup the same way
(`CREATE TABLE IF NOT EXISTS`):

```sql
CREATE TABLE vaults (
  root_doc_id TEXT PRIMARY KEY,
  owner_did   TEXT NOT NULL,
  name        TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_change_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX vaults_owner_name ON vaults (owner_did, lower(name));

CREATE TABLE doc_creators (
  doc_id      TEXT PRIMARY KEY,
  creator_did TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

`doc_creators` is written in three places: by the inbound filter the first
time an authenticated peer sends a frame for an unknown document ID, by
the MCP `create_note` tool, and by vault creation (Z3), which records the
vault's owner as creator of its root document. The write is
`INSERT ... ON CONFLICT DO NOTHING`, then read back, so two peers racing on
one ID cannot both become its creator.

The relay loads `doc_creators` into memory at startup and writes through to
the table. "Unknown to the relay" in Z5 means no entry in that map, so the
filter touches the database only on a document's first frame. Each new row is
also passed to the reachability index (Z4).

### Z3. Vault endpoints

On the sync listener. Member endpoints take a bearer token with the sync
audience.

| Endpoint | Caller | Does |
|---|---|---|
| `GET /vaults` | member | Lists the caller's vaults: root document ID, name, created, last change. A sync client uses this to choose which vault to connect to. |
| `GET /internal/vaults?did=<did>` | Corliss | Lists a member's vaults, same fields. |
| `POST /internal/vaults` `{did, name}` | Corliss | Creates a vault owned by `did`. The relay creates an empty root folder document, records `did` as its creator in `doc_creators`, inserts the `vaults` row, and returns the new vault. `409` if the member already has a vault with that name. |

A vault in every response is one JSON object:

```json
{
  "root_doc_id": "<document ID>",
  "url": "automerge:<document ID>",
  "name": "<vault name>",
  "created_at": "<RFC 3339 timestamp>",
  "last_change_at": "<RFC 3339 timestamp, or null>"
}
```

Both list endpoints return `200` with `{"vaults": [...]}`, oldest first, and
an empty list for a member with none. Create returns `201` with the vault
object.

Errors on the `/internal/` endpoints are `{"error": "<code>"}`: `400` with
`invalid_did` or `invalid_name`, `409` with `name_taken`. A missing or wrong
credential on any of the three is `401` with no JSON body.

Both `/internal/` endpoints are authenticated with the shared service
credential, sent as `Authorization: Bearer <SERVICE_TOKEN>`. The prefix exists so the reverse proxy can leave it unrouted;
it is reachable only on the internal network.

**Vaults are created only here.** No sync client creates or registers a
vault. A client lists the member's vaults, the user picks one, and the
client requests that root document. A member may have any number of
vaults.

Names: 1 to 100 characters after trimming, unique per owner, compared
without regard to case. MCP tools address a note by vault and path, so two
vaults with one name would be ambiguous.

The relay does not check membership on create. Corliss calls it only for a
signed-in member, and a vault whose owner cannot get a token is
unreachable.

Last change comes from `DocHandle::changes` on the vault's documents. It is
held in memory and written to `vaults.last_change_at` at most once a minute
per vault, never per edit.

### Z4. Reachability index

For each vault, the set of document IDs reachable from its root by walking
folder documents. Folder documents list entries shaped `{name, type, url}`.

- Held in memory: `doc_id -> root_doc_id`.
- Built at startup for every row in `vaults`, and when a vault is
  created.
- Rebuilt for a vault when any of its folder documents changes
  (`DocHandle::changes`), at most once a second per vault. A first import
  changes folder documents thousands of times.
- A document linked from two folders of one vault is in the set once. That
  is the normal state part way through a move, because clients add the new
  entry before removing the old one.
- Leaving the set removes a document from path lookups and from search (M4).
  It does not deny the owner, who is still its creator (Z1), and the stored
  document is kept.
- Derived and rebuildable. Never authoritative, never persisted.

**Admission rule.** A document enters a vault's reachable set only if
`doc_creators` names the vault's owner as its creator. Without this, a member
could gain access to someone else's document by adding its URL to their own
folder document. A link to a document created by someone else is ignored and
logged. A link to a document with no `doc_creators` row yet is held as
pending and not logged, because a folder change can arrive before the linked
note's first frame. When the row is written, the pending link is checked
again.

### Z5. Transport filter

`handle_socket` stops calling `accept_axum`. It builds a
`samod::Transport` from the websocket itself and wraps both directions,
then calls `AcceptorHandle::accept`. The filter holds the connection's DID
and token expiry.

Envelope. Each frame is a CBOR map with string keys. The filter reads
`type`, `senderId`, `targetId` and `documentId` and leaves the rest untouched.
A frame that repeats one of those keys is unparseable: samod keeps the last
value of a repeated key, so a reader that kept the first would check one
document while samod acted on another.

Inbound, by `type`:

| Type | Action |
|---|---|
| `join`, `leave`, `error` | Pass |
| `request`, `sync`, `ephemeral`, `doc-unavailable` | If the document is unknown to the relay, record the creator (Z2). Then `may_open`. Pass if true. If false, drop the frame and send `doc-unavailable` for that document back to the peer. |
| `remote-subscription-change`, `remote-heads-changed` | Drop |
| Unparseable, or any other type | Drop and log at warn |

Outbound: frames carrying a `documentId` pass only if `may_open` is true.
Others pass, except an unparseable frame, which is withheld. This is a second wall behind the inbound check.

A denied document and a document that does not exist look the same to the
peer.

Expiry: at the token's `exp` the filter sends a websocket close with code
`1008` and reason `token expired`, and ends the inbound stream, which makes
samod drop the connection.

### Z6. Announce policy

The repo is built with `NeverAnnounce`. The relay never offers a document
unasked and never asks one peer for a document on behalf of another. Clients
request the documents their folder documents list. A change still reaches
every peer that has already synced that document.

A client therefore requests every document it wants changes for, on every
connection. See open question 7.

## MCP service

### M1. Shape

- Same process and same `samod::Repo` as sync. Tools read and edit the live
  documents, and edits reach connected peers through samod's normal sync.
- Its own listener, so sync and MCP traffic stay separate in the proxy and in
  logs. It is mounted at the path of `MCP_AUDIENCE`, the root when that URL
  has none. With `REQUIRE_AUTH=false` there is no member to act as and the
  listener is not started.
- `rmcp`'s `StreamableHttpService`, mounted on an axum router.
- `allowed_hosts` set to the public MCP host. rmcp's default accepts only
  loopback and answers `403` to anything else.
- Stateless: `legacy_session_mode: false`. No session ID is issued, and GET
  and DELETE answer `405`. Each request carries its own token.
- `json_response: true`. A tool call returns one JSON body. rmcp falls back to
  an SSE response only if a handler emits a notification before its result,
  which no tool here does.
- Tools never push unprompted and should return within 60 seconds, the
  shortest first-byte timeout among the clients served.

### M2. OAuth handshake

- `GET /.well-known/oauth-protected-resource<MCP path>` on the MCP host
  returns `resource` (the public MCP URL in canonical form: lowercase scheme
  and host, no trailing slash, no default port) and `authorization_servers`
  (the issuer).
- An axum middleware in front of the MCP service verifies the bearer token
  with `CorlissVerifier`, using the MCP audience.
- No token or a bad token: `401` with
  `WWW-Authenticate: Bearer resource_metadata="https://<MCP host>/.well-known/oauth-protected-resource<MCP path>"`.
- On success the middleware stores the `Did` in the request's extensions.
  rmcp passes the request parts to tool handlers, which read the `Did` from
  there. Tools never see the token.

Nothing here is specific to one MCP client.

### M3. Tools

Every tool acts as the caller's DID and calls `may_open` on every document
it touches.

Tools address a note by vault and path, resolved through the folder
documents at call time. A note with no folder entry cannot be reached by any
tool. `create_note` refuses a path that already has an entry.

- **Vault.** Every tool but `list_vaults` takes an optional `vault` name,
  matched without regard to case. It may be left out when the caller has
  exactly one vault; with more, the tool refuses and lists their names.
- **Admission at call time.** A tool follows an entry only to a document the
  caller created, the same rule the reachability index applies. It does not
  wait for the index, so a note is readable the moment it is created.
- **Paths** match names after NFC and case folding, and answers spell a path
  as the folders do.
- **`list_notes`** takes `recursive`, off by default.
- **`create_note`** creates the folders on the way that are missing, and
  takes only a name ending in `.md`.
- **`edit_note`** takes `old_text`, `new_text` and `replace_all`. Several
  matches without `replace_all` is refused. What `old_text` and `new_text`
  share at either end is left untouched; only the differing middle is
  spliced.
- **`append_note`** starts the added text on a new line.
- **Refusals** (no such note, already exists, ambiguous match) come back as a
  tool result marked as an error, with text the model can act on.

| Tool | Does |
|---|---|
| `list_vaults` | The caller's vaults |
| `list_notes` | Notes and folders under a path in a vault |
| `read_note` | A note's markdown |
| `search_notes` | Text search across one vault |
| `create_note` | New note at a path. Creates the document, records the creator, adds the entry to the folder document. |
| `edit_note` | Find and replace, applied as text splices |
| `append_note` | Append text to a note |

Writes are targeted text edits. No tool replaces a whole document. Tools use
`DocHandle::with_document_async` so a slow edit does not block the runtime.

### M4. Search

No index. Each search walks the vault's folders and reads every note's text
from the documents the relay already holds in memory. A deleted note is not
found, and a moved or renamed note is returned at its new path, because the
walk is the folders as they are at that moment.

A note matches when it contains every word of the query, in its text or its
path, without regard to case. Results are ordered by how often the words
appear, and carry up to three matching lines each. Default 20 results, at
most 50.

An index (in memory, or a Postgres projection) is the next step if a search
gets slow. Measure on a real vault first.

## Configuration

All prefixed `SCN_SYNC_RELAY_`.

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | required | Unchanged |
| `BIND` | `0.0.0.0:7030` | Unchanged. Sync and vault endpoints. |
| `REQUIRE_AUTH` | `true` | Now runnable when true |
| `OIDC_ISSUER` | required when auth is on | Expected `iss` |
| `OIDC_JWKS_URL` | required when auth is on | |
| `SYNC_AUDIENCE` | required when auth is on | Public sync URL |
| `MCP_BIND` | `0.0.0.0:7031` | MCP listener |
| `MCP_AUDIENCE` | required when auth is on | Public MCP URL in canonical form: lowercase scheme and host, no trailing slash, no default port. Also the `resource` value and the source of `allowed_hosts`. |
| `SERVICE_TOKEN` | required when auth is on | Shared credential for `/internal/vaults`, list and create |

`/health` keeps reporting the auth mode, which becomes `corliss` when the
verifier is active.

## Module layout

| File | Holds |
|---|---|
| `src/auth.rs` | `DidVerifier`, `AllowAll`, `CorlissVerifier`, JWKS cache |
| `src/authz.rs` | `may_open`, `vaults` and `doc_creators` queries |
| `src/reach.rs` | Reachability index and the folder document walk |
| `src/wire.rs` | CBOR envelope reader, `doc-unavailable` writer |
| `src/filter.rs` | Transport filter and expiry |
| `src/vaults.rs` | `/vaults` and `/internal/vaults` handlers, vault creation |
| `src/mcp/` | Server setup, auth middleware, tools, search |
| `src/config.rs` | New settings |
| `src/main.rs` | Wiring, two listeners |

## Test plan

Unit tests:

- `wire`: round trip against frames produced by samod; unparseable input.
- `filter`: allow, deny with `doc-unavailable`, new document recorded,
  outbound drop, close at expiry.
- `authz` and `reach`: owner allowed, other member denied, unlinked document
  allowed only to its creator, foreign link ignored by the admission rule; a
  note linked from two folders; a note whose entry is removed stays open to
  its creator and is absent from tools and search; a link that arrives before
  the note's first frame is admitted once the creator row is written.
- `auth`: good token, expired, wrong audience, wrong issuer, unknown `kid`
  triggering one refetch.
- `vaults`: create returns a vault whose root document the owner can open
  and no one else can; a duplicate name for one owner is `409`; the same
  name for two owners is allowed; a missing or wrong service credential is
  refused.

Integration tests, with a second samod repo acting as the client against the
relay's router:

| Acceptance check | Test |
|---|---|
| 1. No token, expired token or wrong audience gets `401` before upgrade | HTTP requests against `/` |
| 2. Member A cannot open or learn of member B's documents, by sync or MCP | Client as A requests B's document ID and gets unavailable; MCP tools as A return not found; no outbound frame for B's documents reaches A |
| 3. A connection closes at token expiry | Short-lived token, assert the socket closes |
| 4. An MCP client can list, read, search and edit | Tool calls over Streamable HTTP |
| 5. An MCP edit reaches a sync client and a sync edit is visible to MCP | One client connected, edit each way |
| 6. A restart loses nothing, including vault records | Create a vault through `/internal/vaults`, rebuild the app on the same database, list it |

Checks 4 and 5 against real MCP clients and Obsidian on iOS with the
scn-obsidian plugin are verified on the deployed relay, not in this repo's
tests.

## Open questions

1. Settled. See "Document schema".
2. **Client reaction to `doc-unavailable` on a denied push.** Not verified
   against the JS client. It decides whether a denied write fails quietly or
   surfaces an error.
3. **MCP session mode.** Stateless, narrowed to a client test. The MCP
   specification makes sessions optional through 2025-11-25 and removes them
   in 2026-07-28, and neither Anthropic's connector docs nor Claude Code's
   docs require a session ID or the GET stream. Not yet run against the real
   clients. On the deployed relay, for Claude web, iOS, Desktop and Claude
   Code: connect, list tools, read, edit, then restart the relay and call a
   tool again without reconnecting. Pass means no client action is needed
   after the restart. If a hosted client fails, fall back to rmcp's in-memory
   sessions and accept a reconnect after each restart.
4. **`/internal/vaults` path.** A separate path so the proxy can leave it
   unrouted, in place of a `did` parameter on the public `/vaults`. Confirm.
5. **Bulk edits by a model.** No rate limit or proposal step in this spec.
   Decide before the first incident.
6. **Upstream.** samod's issue tracker was not checked for planned
   access-control hooks. If one lands, the inbound half of the filter could
   move into it.
7. **Reconnect cost.** Access tokens last 15 minutes and the relay closes
   each connection at `exp` (A3). The relay never announces (Z6), so on every
   reconnect the client starts sync for every document it holds. For a vault
   of N notes that is N handshakes per device every 15 minutes, and samod
   keeps each requested document loaded. Measure on the deployed relay with a
   real vault: handshake time, relay memory, and Postgres reads per
   reconnect. If the cost is too high, the candidates are a longer sync token
   lifetime or renewing a token on an open connection. Neither is designed
   here.
8. **A cap on vaults per member.** None in this spec. Each vault costs one
   small document and one row, so the risk is clutter, not load. Add a cap
   if it becomes a problem.

## Rollout

1. Land in this repo, bump the version, push an annotated tag.
2. In the deployment repo: new env vars, the MCP port, `REQUIRE_AUTH=true`,
   and the two public routes, in the same change. Query strings stripped from
   proxy access logs.
3. Update this repo's README: status, configuration table, endpoints.
