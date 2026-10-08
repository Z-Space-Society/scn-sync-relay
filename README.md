# scn-sync-relay

An Automerge sync relay for the Shared Computer Network. It speaks the
automerge-repo WebSocket protocol, so a standard `@automerge/automerge-repo`
client connects to it with nothing changed but a token in the URL, and it
persists documents to Postgres. It also serves those documents to MCP clients.

Built on [`samod`](https://crates.io/crates/samod), the Rust automerge-repo
implementation. A single static binary under systemd: no Node runtime, no
container.

## Status: Phase B

Every connection is authenticated as an SCN member and can open only that
member's own documents.

- **Sign-in is Corliss's.** The relay accepts access tokens issued by
  [Corliss](https://github.com/Z-Space-Society/Corliss), the network's OAuth
  provider, and resolves each to the member's DID. Corliss re-checks
  membership every time it issues one and they last 15 minutes, so access
  stops within one token lifetime of leaving the network.
- **Each vault has one owner.** A vault is a tree of folder and note
  documents under a root. Only its owner can open them. Sharing is not built.
- **MCP is built in.** A second listener serves the member's notes to an MCP
  client, acting as that member, from the same documents sync uses.

What this does not do:

- **It does not unshare the past.** A former member keeps whatever their
  devices already hold.
- **It is not end-to-end encrypted.** The relay, and so its operators, can
  read every note. Notes sit in plaintext in Postgres.

The design is in [`docs/specs/0001-spec-phase-b`](docs/specs/0001-spec-phase-b/0001-spec-phase-b.md).

## Configuration

All settings come from the environment; systemd loads them from an
`EnvironmentFile` written by Ansible.

| Variable | Default | Notes |
| --- | --- | --- |
| `SCN_SYNC_RELAY_DATABASE_URL` | *required* | No in-memory fallback: a relay that silently ran on memory would look healthy until its first restart. |
| `SCN_SYNC_RELAY_BIND` | `0.0.0.0:7030` | Sync and the vault endpoints. Bind a wildcard. Binding a literal container address loses a cold-boot race with `systemd-networkd` and comes up loopback-only. |
| `SCN_SYNC_RELAY_REQUIRE_AUTH` | `true` | Defaults on, so the safe posture is the one you get by forgetting. See "Running without auth". |
| `SCN_SYNC_RELAY_OIDC_ISSUER` | *required with auth* | The `iss` every token must carry: Corliss's public URL, no trailing slash. |
| `SCN_SYNC_RELAY_OIDC_JWKS_URL` | *required with auth* | Where to fetch Corliss's signing keys. Use its internal address. |
| `SCN_SYNC_RELAY_SYNC_AUDIENCE` | *required with auth* | The `aud` a sync token must carry: the public sync URL, spelled exactly as Corliss's `OIDC_RESOURCES` spells it. |
| `SCN_SYNC_RELAY_MCP_AUDIENCE` | *required with auth* | The `aud` an MCP token must carry: the public MCP URL, in lowercase with no trailing slash and no default port. Also the only `Host` the MCP service answers to, and its path is where the service is mounted. |
| `SCN_SYNC_RELAY_MCP_BIND` | `0.0.0.0:7031` | The MCP listener. |
| `SCN_SYNC_RELAY_SERVICE_TOKEN` | *required with auth* | The shared credential Corliss presents on `/internal/vaults`. |
| `RUST_LOG` | `scn_sync_relay=info,samod=info` | Standard `tracing` filter. |

With auth on and any of the required settings missing or blank, the relay
refuses to start and names the one it wants.

- **The two audiences must match Corliss character for character.** A token
  whose `aud` differs by a trailing slash is refused, and the only symptom is
  a `401`. Define each URL once in the deployment and render it to both
  services.
- **The JWKS is cached.** It is fetched at startup and again when a token
  names a key the relay has not seen, at most every 30 seconds. If Corliss is
  down when the relay starts, the relay starts anyway and refuses every token
  until a fetch succeeds.

### Running without auth

`SCN_SYNC_RELAY_REQUIRE_AUTH=false` runs the relay with no verifier and no
filter: any peer that can reach the port can sync any document it holds. It is
for local work and is only sound where the service has no route in. The MCP
service is not started in this mode, because there is no member for it to act
as.

## Endpoints

On the sync listener (`BIND`):

| Path | Caller | Purpose |
| --- | --- | --- |
| `GET /` | sync client | WebSocket upgrade; the automerge-repo sync protocol. **This is the one clients use**: `WebSocketClientAdapter` connects to exactly the URL it is given and appends no path, so clients are configured with a bare `wss://host`. |
| `GET /sync` | sync client | The same handler, for a client configured with an explicit path. |
| `GET /vaults` | member | The caller's vaults. `Authorization: Bearer` with a sync token. |
| `GET /internal/vaults?did=` | Corliss | A member's vaults. `Authorization: Bearer` with the service token. |
| `POST /internal/vaults` | Corliss | Create a vault: `{"did", "name"}`. Returns `201` and the vault. |
| `GET /health` | anyone | Liveness and the current auth mode. Does not touch Postgres, so a database blip cannot get the relay restarted out from under live connections. |

On the MCP listener (`MCP_BIND`):

| Path | Purpose |
| --- | --- |
| `POST <MCP path>` | MCP over Streamable HTTP. `Authorization: Bearer` with an MCP token. |
| `GET /.well-known/oauth-protected-resource<MCP path>` | Which authorization server issues tokens for this resource. Unauthenticated; it is how an MCP client finds Corliss. |

Things the proxy in front has to get right:

- **Do not route `/internal/`.** Those endpoints are for Corliss on the
  internal network. The service token is the only thing guarding them.
- **Do not log query strings on the sync route.** A browser or phone
  websocket cannot send an `Authorization` header, so a sync client connects
  to `wss://host/?access_token=<token>`. The relay never logs it.

### Sync

A connection with no token, or an expired or wrong-audience one, gets `401`
before the upgrade. Once connected:

- A request for a document the member may not open is answered with
  `doc-unavailable`, the same answer a document that does not exist gets.
- The relay never offers a document unasked. A client requests the documents
  its folder documents list, on every connection.
- The connection is closed with code `1008` and reason `token expired` when
  its token's `exp` passes. The client reconnects with a fresh token.

### Vaults

A vault is one JSON object:

```json
{
  "root_doc_id": "<document ID>",
  "url": "automerge:<document ID>",
  "name": "<vault name>",
  "created_at": "<RFC 3339 timestamp>",
  "last_change_at": "<RFC 3339 timestamp, or null>"
}
```

Listings return `{"vaults": [...]}`, oldest first. Errors on the internal
endpoints are `{"error": "<code>"}`: `400` with `invalid_did` or
`invalid_name`, `409` with `name_taken`. Names are 1 to 100 characters and
unique per owner whatever their letter case.

Vaults are created through `POST /internal/vaults` and nowhere else. No sync
client makes one.

### MCP tools

Every tool acts as the member the token names.

| Tool | Does |
| --- | --- |
| `list_vaults` | The caller's vaults |
| `list_notes` | Notes and folders in a vault or one of its folders |
| `read_note` | A note's markdown |
| `search_notes` | Notes containing every word of a query |
| `create_note` | A new note at a path, with any folders on the way |
| `edit_note` | Replace one piece of a note's text with another |
| `append_note` | Add text to the end of a note |

The service is stateless: no session is issued and each request carries its
own token, so a relay restart needs nothing from the client. There is no tool
to delete a note.

## Storage

Three tables, created at startup. The deployment provisions the database and
its owning role, not the schema.

```sql
CREATE TABLE storage (key TEXT PRIMARY KEY, value BYTEA NOT NULL);
CREATE INDEX storage_key_prefix ON storage (key text_pattern_ops);

CREATE TABLE vaults (
  root_doc_id    TEXT PRIMARY KEY,
  owner_did      TEXT NOT NULL,
  name           TEXT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_change_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX vaults_owner_name ON vaults (owner_did, lower(name));

CREATE TABLE doc_creators (
  doc_id      TEXT PRIMARY KEY,
  creator_did TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

`storage` holds the documents. `vaults` names each vault's owner and root
document. `doc_creators` records who first sent each document, and is what
decides ownership: losing it loses every member's access to their own notes,
so it is as much the store of record as `storage` is.

samod's `StorageKey` guarantees no component contains a `/`, so a key round
trips as `Display` out and `split('/')` back, with no escaping.

`text_pattern_ops` is load-bearing: the default opclass follows the database
collation and will not serve a `LIKE 'prefix%'` scan, which would quietly turn
every range read into a full scan of a table that only grows.

## Building

```sh
cargo build --release
```

`Cargo.lock` and `rust-toolchain.toml` are committed, so two builds months
apart produce the same binary from the same contents. Build against the
target's glibc — building on macOS would need a cross-compile or a static musl
target.

## Testing

```sh
DATABASE_URL=postgres://localhost/postgres cargo test
```

Most tests need a Postgres server. `DATABASE_URL` names any database on it
that the user may create databases from: each test gets a database of its own
and drops it when it passes.

## Releasing

Deployment checks out an **annotated tag**, so the tag has to reach the remote:

```sh
git tag -a v0.1.0 -m "v0.1.0"
git push origin main --follow-tags
git ls-remote --tags origin       # the check that matters
```

A tag that exists only locally fails at checkout with `pathspec 'v0.1.0' did
not match`, which reads like a bad version pin rather than an unpushed tag.

## License

Apache-2.0.
