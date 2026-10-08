# scn-sync-relay

An Automerge sync relay for the Shared Computer Network. It speaks the
automerge-repo WebSocket protocol — so standard `@automerge/automerge-repo`
clients connect to it unmodified — and persists documents to Postgres.

Built on [`samod`](https://crates.io/crates/samod), the Rust automerge-repo
implementation. A single static binary under systemd: no Node runtime, no
container.

## Status: Phase A — no membership enforcement

**This build syncs any document it holds to any peer that can reach it.** There
is no access control. It is meant to be deployed on an internal bridge with no
route through a reverse proxy, holding nothing that matters, to prove protocol
interoperability and the deployment before the enforcement layer is written.

The binary refuses to start unless you say so explicitly:

```
SCN_SYNC_RELAY_REQUIRE_AUTH is on, but this build has no DID verifier
(service auth is Phase B). Set SCN_SYNC_RELAY_REQUIRE_AUTH=false to run
the unauthenticated Phase A relay, and only where it has no route in.
```

Phase B adds ATProto service-auth verification and authorization by
reachability from an ATProto Space's manifest document. The design is recorded
in `zai-ops` as ADR-0007.

## Configuration

All settings come from the environment; systemd loads them from an
`EnvironmentFile` written by Ansible.

| Variable | Default | Notes |
| --- | --- | --- |
| `SCN_SYNC_RELAY_DATABASE_URL` | *required* | No in-memory fallback — a relay that silently ran on memory would look healthy until its first restart. |
| `SCN_SYNC_RELAY_BIND` | `0.0.0.0:7030` | Bind a wildcard. Binding a literal container address loses a cold-boot race with `systemd-networkd` and comes up loopback-only. |
| `SCN_SYNC_RELAY_REQUIRE_AUTH` | `true` | Defaults on, so the safe posture is the one you get by forgetting. Phase A must set it to `false`. |
| `RUST_LOG` | `scn_sync_relay=info,samod=info` | Standard `tracing` filter. |

## Endpoints

| Path | Purpose |
| --- | --- |
| `GET /` | WebSocket upgrade; the automerge-repo sync protocol. **This is the one clients use** — `WebSocketClientAdapter` connects to exactly the URL it is given and appends no path, and the reference sync server serves at the root, so clients are configured with a bare `ws://host:port`. |
| `GET /sync` | The same handler, for a client configured with an explicit path. |
| `GET /health` | Liveness and the current auth mode. Does not touch Postgres, so a database blip cannot get the relay restarted out from under live connections. |

## Storage

One table, created at startup — the deployment provisions the database and its
owning role, not the schema.

```sql
CREATE TABLE storage (key TEXT PRIMARY KEY, value BYTEA NOT NULL);
CREATE INDEX storage_key_prefix ON storage (key text_pattern_ops);
```

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
