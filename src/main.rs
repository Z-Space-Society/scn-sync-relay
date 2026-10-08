//! An Automerge sync relay for the Shared Computer Network.
//!
//! Speaks the automerge-repo WebSocket protocol via `samod`, and persists to
//! Postgres. A connection is authenticated as a member's DID before the
//! websocket upgrade; see `auth.rs` and [`build_verifier`].

mod auth;
mod authz;
mod config;
mod filter;
mod mcp;
mod reach;
mod storage;
mod vaults;
mod wire;

use std::future::IntoFuture;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use samod::{AcceptorHandle, NeverAnnounce, Repo};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;

use auth::{AllowAll, CorlissVerifier, DidVerifier, Verified};
use authz::Authz;
use config::Config;
use storage::PostgresStorage;

#[derive(Clone)]
struct AppState {
    acceptor: AcceptorHandle,
    verifier: Arc<dyn DidVerifier>,
    /// The audience a sync token must carry. Empty when nothing is verified.
    sync_audience: Arc<str>,
    authz: Authz,
    /// Whether connections go through the filter. Off only with no verifier,
    /// where there is no DID to decide by.
    enforce: bool,
    /// What Corliss presents on `/internal/vaults`. `None` refuses every call.
    service_token: Option<Arc<str>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "scn_sync_relay=info,samod=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    let verifier = build_verifier(&config).await?;

    // A small pool: this is a relay, not a web app. Connections are held only
    // for the duration of a storage call, and samod serialises per document.
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&config.database_url)
        .await
        .context("could not connect to Postgres")?;

    let store = PostgresStorage::new(pool.clone());
    store
        .migrate()
        .await
        .context("could not create the storage schema")?;

    // The relay never offers a document unasked, and never asks one peer for
    // a document on behalf of another. A peer gets what it requests and may
    // open, and a change still reaches every peer already syncing that
    // document.
    let repo = Repo::build_tokio()
        .with_storage(store)
        .with_announce_policy(NeverAnnounce)
        .load()
        .await;
    let authz = Authz::load(pool, repo.clone())
        .await
        .context("could not load the ownership records")?;

    // The URL is used only to identify this endpoint in samod's own logs; it
    // is not something the relay binds or dials.
    let acceptor = repo
        .make_acceptor(
            format!("ws://{}/sync", config.bind)
                .parse()
                .context("bind address does not form a valid URL")?,
        )
        .map_err(|_| anyhow::anyhow!("repo stopped before it could accept connections"))?;

    let app = router(AppState {
        acceptor,
        verifier: Arc::clone(&verifier),
        sync_audience: config
            .auth
            .as_ref()
            .map(|auth| auth.sync_audience.as_str())
            .unwrap_or_default()
            .into(),
        authz: authz.clone(),
        enforce: config.require_auth,
        service_token: config.service_token.as_deref().map(Arc::from),
    });

    let listener = tokio::net::TcpListener::bind(&config.bind)
        .await
        .with_context(|| format!("could not bind {}", config.bind))?;

    tracing::info!(
        bind = %config.bind,
        auth = verifier.name(),
        "scn-sync-relay listening"
    );
    let sync = axum::serve(listener, app).with_graceful_shutdown(shutdown());

    // The MCP service acts as the member a token names. With no verifier
    // there is no member, so it is not started.
    let Some(auth) = &config.auth else {
        tracing::warn!(
            "running WITHOUT a membership gate: any peer that can reach this \
             port can sync any document this relay holds. This is only sound \
             while the service has no route through the proxy. The MCP \
             service is not started."
        );
        return sync.await.context("server error");
    };

    let mcp_app = mcp::router(
        authz,
        Arc::clone(&verifier),
        &auth.mcp_audience,
        &auth.oidc_issuer,
    )?;
    let mcp_listener = tokio::net::TcpListener::bind(&config.mcp_bind)
        .await
        .with_context(|| format!("could not bind {}", config.mcp_bind))?;
    tracing::info!(bind = %config.mcp_bind, audience = %auth.mcp_audience, "MCP service listening");
    let mcp = axum::serve(mcp_listener, mcp_app).with_graceful_shutdown(shutdown());

    tokio::try_join!(sync.into_future(), mcp.into_future()).context("server error")?;

    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        // The websocket lives at BOTH the root and /sync, and the root is the one
        // that matters. `automerge-repo`'s WebSocketClientAdapter connects to
        // exactly the URL it is given and appends no path, and the reference
        // sync server serves at the root — so clients are configured with a bare
        // `ws://host:port`. Serving only /sync means a stock client gets a 404
        // instead of an upgrade, which surfaces as "sync silently never works".
        .route("/", get(sync))
        .route("/sync", get(sync))
        .route("/health", get(health))
        .route("/vaults", get(vaults::list_own))
        .route(
            "/internal/vaults",
            get(vaults::list_for_member).post(vaults::create),
        )
        .with_state(state)
}

/// Pick the verifier, or refuse to start.
///
/// Fails closed on purpose. `require_auth` defaults to true, and `Config`
/// refuses to load that way without the issuer settings, so the *only* way to
/// run the ungated relay is to say out loud that you want it.
async fn build_verifier(config: &Config) -> Result<Arc<dyn DidVerifier>> {
    match &config.auth {
        Some(auth) => Ok(Arc::new(
            CorlissVerifier::new(auth.oidc_issuer.clone(), auth.oidc_jwks_url.clone()).await?,
        )),
        None => Ok(Arc::new(AllowAll)),
    }
}

/// Liveness only. It reports that the process is up and which auth mode it is
/// in; it deliberately does not touch Postgres, so a database blip cannot get
/// the relay restarted out from under live connections.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, format!("ok auth={}\n", state.verifier.name()))
}

#[derive(Deserialize)]
struct SyncQuery {
    access_token: Option<String>,
}

async fn sync(
    ws: WebSocketUpgrade,
    Query(query): Query<SyncQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Authentication happens *before* the upgrade, so a rejected peer gets an
    // HTTP status it can act on rather than a socket that opens and then dies.
    //
    // The token rides in the URL because a browser or phone WebSocket cannot
    // send an Authorization header. That makes the query string a secret:
    // nothing here logs it, and the proxy in front must not either.
    let verified = match state
        .verifier
        .verify(query.access_token.as_deref(), &state.sync_audience)
        .await
    {
        Ok(verified) => verified,
        Err(e) => {
            // The reason goes to the log and not to the peer.
            tracing::info!(error = %e, "refused a connection");
            return (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
        }
    };

    ws.on_upgrade(move |socket| handle_socket(socket, state, verified))
        .into_response()
}

async fn handle_socket(socket: WebSocket, state: AppState, verified: Verified) {
    let did = verified.did;
    if state.enforce {
        let filter = filter::Filter::new(state.authz, did);
        filter::run(socket, &state.acceptor, filter, verified.expires_at).await;
        return;
    }

    // Ungated: nobody was authenticated, so there is no DID to filter by and
    // samod is handed the socket directly.
    match state.acceptor.accept_axum(socket, None) {
        Ok(_conn) => {
            // samod drives the connection on its own task, so there is nothing
            // to hold here. Dropping the handle does not close the socket.
            tracing::info!(%did, "peer connected");
        }
        Err(_) => {
            tracing::warn!(%did, "repo stopped; dropping connection");
        }
    }
}

/// SIGTERM is what systemd sends on `restart` and `stop`, so handling it is
/// what makes a deploy close sockets cleanly instead of severing them.
async fn shutdown() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    use auth::tests::{Issuer, TokenSpec, SYNC_AUDIENCE};
    use serde_json::{json, Value};
    use sqlx::PgPool;

    const SERVICE_TOKEN: &str = "test-service-token";
    const ALICE: &str = "did:plc:alice";
    const BOB: &str = "did:plc:bob";

    /// A running relay: both listeners on loopback ports, on the test's own
    /// database, gated by a verifier that trusts the test issuer.
    struct Relay {
        /// Base URL of the sync listener.
        base: String,
        /// The MCP URL, which is also the audience an MCP token must carry.
        mcp: String,
        authz: Authz,
        repo: Repo,
    }

    /// Start a relay. Calling it twice on one pool is a restart.
    async fn start(pool: &PgPool) -> Relay {
        let issuer = Issuer::start().await;
        let verifier: Arc<dyn DidVerifier> = Arc::new(issuer.verifier().await);
        let (authz, repo) = authz::tests::open(pool).await;
        let acceptor = repo
            .make_acceptor("ws://relay.test/sync".parse().unwrap())
            .unwrap();
        let app = router(AppState {
            acceptor,
            verifier: Arc::clone(&verifier),
            sync_audience: SYNC_AUDIENCE.into(),
            authz: authz.clone(),
            enforce: true,
            service_token: Some(SERVICE_TOKEN.into()),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mcp = format!("http://{}", listener.local_addr().unwrap());
        let app = mcp::router(authz.clone(), verifier, &mcp, auth::tests::ISSUER).unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        Relay {
            base,
            mcp,
            authz,
            repo,
        }
    }

    async fn relay(pool: &PgPool) -> (String, Authz) {
        let relay = start(pool).await;
        (relay.base, relay.authz)
    }

    /// Ask for a websocket upgrade and report the status of the answer.
    async fn upgrade(url: &str) -> StatusCode {
        reqwest::Client::new()
            .get(url)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
            .unwrap()
            .status()
    }

    fn member_token(did: &str) -> String {
        TokenSpec::default().claim("sub", json!(did)).sign()
    }

    async fn create_vault(base: &str, did: &str, name: &str) -> (StatusCode, Value) {
        let response = reqwest::Client::new()
            .post(format!("{base}/internal/vaults"))
            .bearer_auth(SERVICE_TOKEN)
            .json(&json!({ "did": did, "name": name }))
            .send()
            .await
            .unwrap();
        (response.status(), response.json().await.unwrap())
    }

    /// The names of the vaults a listing returns.
    async fn names(request: reqwest::RequestBuilder) -> Vec<String> {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        body["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .map(|vault| vault["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[sqlx::test(migrations = false)]
    async fn good_token_upgrades(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        let token = TokenSpec::default().sign();
        for path in ["/", "/sync"] {
            let status = upgrade(&format!("{base}{path}?access_token={token}")).await;
            assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS, "{path}");
        }
    }

    #[sqlx::test(migrations = false)]
    async fn bad_or_missing_token_gets_401_before_upgrade(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        let expired = TokenSpec::default().claim("exp", json!(1)).sign();
        let wrong_audience = TokenSpec::default()
            .claim("aud", json!("https://mcp.corliss.test"))
            .sign();
        for query in [
            String::new(),
            "?access_token=".to_string(),
            "?access_token=garbage".to_string(),
            format!("?access_token={expired}"),
            format!("?access_token={wrong_audience}"),
        ] {
            let status = upgrade(&format!("{base}/{query}")).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{query}");
        }
    }

    #[sqlx::test(migrations = false)]
    async fn corliss_creates_a_vault_only_its_owner_can_open(pool: PgPool) {
        let (base, authz) = relay(&pool).await;

        let (status, vault) = create_vault(&base, ALICE, "Notes").await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(vault["name"], "Notes");
        assert_eq!(
            vault["url"],
            format!("automerge:{}", vault["root_doc_id"].as_str().unwrap())
        );
        assert!(vault["created_at"].is_string());
        assert!(vault["last_change_at"].is_null());

        let root = vault["root_doc_id"].as_str().unwrap().parse().unwrap();
        assert!(authz.may_open(&auth::Did(ALICE.into()), &root));
        assert!(!authz.may_open(&auth::Did(BOB.into()), &root));
    }

    #[sqlx::test(migrations = false)]
    async fn create_refuses_duplicates_and_bad_input(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        create_vault(&base, ALICE, "Notes").await;

        let (status, body) = create_vault(&base, ALICE, "NOTES").await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "name_taken");

        let (status, _) = create_vault(&base, BOB, "Notes").await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, body) = create_vault(&base, ALICE, "  ").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_name");

        let (status, body) = create_vault(&base, "alice", "Other").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_did");
    }

    #[sqlx::test(migrations = false)]
    async fn listings_show_only_the_members_own_vaults(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        create_vault(&base, ALICE, "Notes").await;
        create_vault(&base, ALICE, "Work").await;
        create_vault(&base, BOB, "Private").await;
        let client = reqwest::Client::new();

        let own = client
            .get(format!("{base}/vaults"))
            .bearer_auth(member_token(ALICE));
        assert_eq!(names(own).await, ["Notes", "Work"]);

        let for_bob = client
            .get(format!("{base}/internal/vaults?did={BOB}"))
            .bearer_auth(SERVICE_TOKEN);
        assert_eq!(names(for_bob).await, ["Private"]);

        let nobody = client
            .get(format!("{base}/vaults"))
            .bearer_auth(member_token("did:plc:carol"));
        assert!(names(nobody).await.is_empty());
    }

    #[sqlx::test(migrations = false)]
    async fn vault_endpoints_refuse_the_wrong_credential(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        let client = reqwest::Client::new();
        let member = member_token(ALICE);
        let internal = format!("{base}/internal/vaults");
        let for_alice = format!("{internal}?did={ALICE}");
        let body = json!({ "did": ALICE, "name": "Notes" });

        for request in [
            // The member endpoint: no token, the service credential, a token
            // for another audience.
            client.get(format!("{base}/vaults")),
            client.get(format!("{base}/vaults")).bearer_auth(SERVICE_TOKEN),
            client.get(format!("{base}/vaults")).bearer_auth(
                TokenSpec::default()
                    .claim("aud", json!("https://mcp.corliss.test"))
                    .sign(),
            ),
            // The internal endpoints: no credential, a wrong one, a member's
            // own token.
            client.get(&for_alice),
            client.get(&for_alice).bearer_auth("wrong"),
            client.get(&for_alice).bearer_auth(&member),
            client.post(&internal).json(&body),
            client.post(&internal).json(&body).bearer_auth("wrong"),
            client.post(&internal).json(&body).bearer_auth(&member),
        ] {
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[sqlx::test(migrations = false)]
    async fn a_restart_keeps_vault_records(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        create_vault(&base, ALICE, "Notes").await;

        let (base, _) = relay(&pool).await;
        let own = reqwest::Client::new()
            .get(format!("{base}/vaults"))
            .bearer_auth(member_token(ALICE));
        assert_eq!(names(own).await, ["Notes"]);
    }

    /// Dials the relay's websocket the way a sync client does, token in the
    /// URL.
    struct WsDialer(samod::Url);

    impl samod::Dialer for WsDialer {
        type Error = std::convert::Infallible;

        fn url(&self) -> samod::Url {
            self.0.clone()
        }

        fn connect(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<samod::Transport, samod::DialError<Self::Error>>,
                    > + Send,
            >,
        > {
            use futures::{SinkExt, StreamExt};
            use tokio_tungstenite::tungstenite::{Error, Message};

            let url = self.0.clone();
            Box::pin(async move {
                let (socket, _) = tokio_tungstenite::connect_async(url.as_str())
                    .await
                    .map_err(samod::DialError::transient)?;
                let (sink, stream) = socket.split();
                let stream = stream.filter_map(|message| async move {
                    match message {
                        Ok(Message::Binary(frame)) => Some(Ok(frame.to_vec())),
                        Ok(_) => None,
                        Err(e) => Some(Err(e)),
                    }
                });
                let sink = sink.with(|frame: Vec<u8>| async move {
                    Ok::<_, Error>(Message::Binary(frame.into()))
                });
                Ok(samod::Transport::new(Box::pin(stream), Box::pin(sink)))
            })
        }
    }

    fn sync_url(base: &str, token: &str) -> String {
        format!("{}/?access_token={token}", base.replace("http://", "ws://"))
    }

    /// A sync client of its own, connected to the relay as `did`.
    async fn client(base: &str, did: &str) -> Repo {
        let repo = Repo::build_tokio().load().await;
        let url = sync_url(base, &member_token(did)).parse().unwrap();
        repo.dial(samod::BackoffConfig::default(), Arc::new(WsDialer(url)))
            .unwrap()
            .established()
            .await
            .unwrap();
        repo
    }

    /// A document with one key set, so there is something to tell apart from
    /// an empty one.
    fn doc_with(key: &str, value: &str) -> automerge::Automerge {
        use automerge::transaction::Transactable;
        let mut doc = automerge::Automerge::new();
        let mut tx = doc.transaction();
        tx.put(automerge::ROOT, key, value).unwrap();
        tx.commit();
        doc
    }

    async fn value_of(handle: &samod::DocHandle, key: &'static str) -> Option<String> {
        use automerge::ReadDoc;
        handle
            .with_document_async(move |doc| {
                let (value, _) = doc.get(automerge::ROOT, key).ok()??;
                Some(value.as_str()?.to_string())
            })
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = false)]
    async fn a_member_syncs_their_own_documents_and_nobody_elses(pool: PgPool) {
        let (base, authz) = relay(&pool).await;
        let laptop = client(&base, ALICE).await;
        let note = laptop.create(doc_with("title", "plan")).await.unwrap();
        let id = note.document_id().clone();
        authz::tests::eventually("the relay has the note", || {
            authz.creator_of(&id).is_some()
        })
        .await;
        assert!(authz.may_open(&auth::Did(ALICE.into()), &id));

        // Her phone gets it from the relay, with the laptop's content.
        let phone = client(&base, ALICE).await;
        let on_phone = phone.find(id.clone()).await.unwrap().expect("found");
        assert_eq!(value_of(&on_phone, "title").await.as_deref(), Some("plan"));

        // Bob is told it is not there, and asking does not make it his.
        let bob = client(&base, BOB).await;
        assert!(bob.find(id.clone()).await.unwrap().is_none());
        assert_eq!(authz.creator_of(&id), Some(auth::Did(ALICE.into())));
    }

    #[sqlx::test(migrations = false)]
    async fn a_vault_root_reaches_its_owner_only(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        let (_, vault) = create_vault(&base, ALICE, "Notes").await;
        let root: samod::DocumentId = vault["root_doc_id"].as_str().unwrap().parse().unwrap();

        let alice = client(&base, ALICE).await;
        assert!(alice.find(root.clone()).await.unwrap().is_some());

        let bob = client(&base, BOB).await;
        assert!(bob.find(root).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = false)]
    async fn a_change_reaches_a_peer_already_syncing_the_document(pool: PgPool) {
        let (base, authz) = relay(&pool).await;
        let laptop = client(&base, ALICE).await;
        let note = laptop.create(doc_with("title", "plan")).await.unwrap();
        let id = note.document_id().clone();
        authz::tests::eventually("the relay has the note", || {
            authz.creator_of(&id).is_some()
        })
        .await;

        let phone = client(&base, ALICE).await;
        let on_phone = phone.find(id).await.unwrap().expect("found");

        note.with_document_async(|doc| {
            use automerge::transaction::Transactable;
            let mut tx = doc.transaction();
            tx.put(automerge::ROOT, "status", "done").unwrap();
            tx.commit();
        })
        .await
        .unwrap();

        // The relay announces nothing, so this arrives only because the phone
        // asked for the document.
        for _ in 0..100 {
            if value_of(&on_phone, "status").await.as_deref() == Some("done") {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("the laptop's edit never reached the phone");
    }

    #[sqlx::test(migrations = false)]
    async fn a_connection_is_closed_when_its_token_expires(pool: PgPool) {
        use futures::StreamExt;
        use tokio_tungstenite::tungstenite::Message;

        let (base, _) = relay(&pool).await;
        let exp = jsonwebtoken::get_current_timestamp() + 2;
        let token = TokenSpec::default().claim("exp", json!(exp)).sign();
        let (mut socket, _) = tokio_tungstenite::connect_async(sync_url(&base, &token))
            .await
            .unwrap();

        let opened = std::time::Instant::now();
        let closed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match socket.next().await {
                    Some(Ok(Message::Close(frame))) => return frame,
                    Some(Ok(_)) => continue,
                    other => panic!("ended without a close frame: {other:?}"),
                }
            }
        })
        .await
        .expect("still open long after the token expired")
        .expect("a close frame with a reason");

        assert_eq!(u16::from(closed.code), 1008);
        assert_eq!(closed.reason.as_str(), "token expired");
        // Not closed early: it stayed open until `exp`.
        assert!(opened.elapsed() >= std::time::Duration::from_millis(900));
    }

    impl Relay {
        fn mcp_token(&self, did: &str) -> String {
            TokenSpec::default()
                .claim("sub", json!(did))
                .claim("aud", json!(self.mcp))
                .sign()
        }

        /// One JSON-RPC request to the MCP service, as a client sends it.
        async fn rpc(&self, token: Option<&str>, method: &str, params: Value) -> reqwest::Response {
            let mut request = reqwest::Client::new()
                .post(&self.mcp)
                .header("accept", "application/json, text/event-stream")
                .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }));
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            request.send().await.unwrap()
        }

        /// Call a tool as a member. Returns whether the tool reported an
        /// error, and the text it answered with.
        async fn call(&self, did: &str, tool: &str, arguments: Value) -> (bool, String) {
            let response = self
                .rpc(
                    Some(&self.mcp_token(did)),
                    "tools/call",
                    json!({ "name": tool, "arguments": arguments }),
                )
                .await;
            assert_eq!(response.status(), StatusCode::OK, "{tool}");
            assert_eq!(
                response.headers()["content-type"],
                "application/json",
                "{tool} answered with a stream"
            );
            let body: Value = response.json().await.unwrap();
            let result = &body["result"];
            assert!(result.is_object(), "{tool}: {body}");
            (
                result["isError"].as_bool().unwrap_or(false),
                result["content"][0]["text"].as_str().unwrap_or_default().to_string(),
            )
        }

        /// Call a tool that is expected to work, and return its answer.
        async fn ok(&self, did: &str, tool: &str, arguments: Value) -> String {
            let (is_error, text) = self.call(did, tool, arguments).await;
            assert!(!is_error, "{tool} refused: {text}");
            text
        }

        /// Call a tool that is expected to refuse, and return why.
        async fn refused(&self, did: &str, tool: &str, arguments: Value) -> String {
            let (is_error, text) = self.call(did, tool, arguments).await;
            assert!(is_error, "{tool} should have refused, said: {text}");
            text
        }
    }

    /// The paths a listing or a search returned.
    fn paths(answer: &str) -> Vec<String> {
        let items: Value = serde_json::from_str(answer).unwrap();
        items
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["path"].as_str().unwrap().to_string())
            .collect()
    }

    #[sqlx::test(migrations = false)]
    async fn mcp_sends_an_unauthenticated_client_to_the_issuer(pool: PgPool) {
        let relay = start(&pool).await;
        let metadata_url = format!("{}/.well-known/oauth-protected-resource", relay.mcp);
        let sync_token = member_token(ALICE);

        for token in [None, Some("garbage"), Some(sync_token.as_str())] {
            let response = relay.rpc(token, "tools/list", json!({})).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers()["www-authenticate"],
                format!("Bearer resource_metadata=\"{metadata_url}\"")
            );
        }

        let metadata: Value = reqwest::get(&metadata_url).await.unwrap().json().await.unwrap();
        assert_eq!(metadata["resource"], relay.mcp);
        assert_eq!(metadata["authorization_servers"], json!([auth::tests::ISSUER]));
    }

    #[sqlx::test(migrations = false)]
    async fn mcp_initializes_and_lists_its_tools(pool: PgPool) {
        let relay = start(&pool).await;
        let token = relay.mcp_token(ALICE);

        let response = relay
            .rpc(
                Some(&token),
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" },
                }),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        // Stateless: no session to carry into the next request.
        assert!(response.headers().get("mcp-session-id").is_none());
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["result"]["serverInfo"]["name"], "scn-sync-relay");

        let body: Value = relay
            .rpc(Some(&token), "tools/list", json!({}))
            .await
            .json()
            .await
            .unwrap();
        let mut names: Vec<_> = body["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "append_note",
                "create_note",
                "edit_note",
                "list_notes",
                "list_vaults",
                "read_note",
                "search_notes"
            ]
        );
    }

    #[sqlx::test(migrations = false)]
    async fn a_member_creates_reads_edits_and_searches_notes(pool: PgPool) {
        let relay = start(&pool).await;
        create_vault(&relay.base, ALICE, "Notes").await;

        // No initialize was ever sent: every call stands on its own token.
        assert!(relay.ok(ALICE, "list_vaults", json!({})).await.contains("Notes"));
        assert_eq!(paths(&relay.ok(ALICE, "list_notes", json!({})).await), [""; 0]);

        relay
            .ok(
                ALICE,
                "create_note",
                json!({ "path": "Projects/plan.md", "content": "# Plan\nShip the relay 🚀 first.\n" }),
            )
            .await;
        relay
            .ok(ALICE, "create_note", json!({ "path": "inbox.md", "content": "relay relay" }))
            .await;

        assert_eq!(
            paths(&relay.ok(ALICE, "list_notes", json!({})).await),
            ["inbox.md", "Projects"]
        );
        assert_eq!(
            paths(&relay.ok(ALICE, "list_notes", json!({ "recursive": true })).await),
            ["inbox.md", "Projects", "Projects/plan.md"]
        );
        assert_eq!(
            paths(&relay.ok(ALICE, "list_notes", json!({ "path": "projects" })).await),
            ["Projects/plan.md"]
        );

        // The edit lands after an emoji, where text positions are easy to
        // get wrong.
        relay
            .ok(
                ALICE,
                "edit_note",
                json!({ "path": "Projects/plan.md", "old_text": "🚀 first", "new_text": "🚀 before Corliss" }),
            )
            .await;
        relay
            .ok(ALICE, "append_note", json!({ "path": "Projects/plan.md", "text": "Then the plugin." }))
            .await;
        relay
            .ok(ALICE, "append_note", json!({ "path": "inbox.md", "text": "second line" }))
            .await;
        assert_eq!(
            relay.ok(ALICE, "read_note", json!({ "path": "Projects/plan.md" })).await,
            "# Plan\nShip the relay 🚀 before Corliss.\nThen the plugin."
        );
        assert_eq!(
            relay.ok(ALICE, "read_note", json!({ "path": "/inbox.md" })).await,
            "relay relay\nsecond line"
        );

        // Best match first, and a note found by a word in its path.
        let found = relay.ok(ALICE, "search_notes", json!({ "query": "RELAY" })).await;
        assert_eq!(paths(&found), ["inbox.md", "Projects/plan.md"]);
        assert!(found.contains("Ship the relay"));
        let found = relay.ok(ALICE, "search_notes", json!({ "query": "projects plugin" })).await;
        assert_eq!(paths(&found), ["Projects/plan.md"]);
        let found = relay.ok(ALICE, "search_notes", json!({ "query": "nothing-says-this" })).await;
        assert!(paths(&found).is_empty());
    }

    #[sqlx::test(migrations = false)]
    async fn tools_refuse_what_they_should(pool: PgPool) {
        let relay = start(&pool).await;
        create_vault(&relay.base, ALICE, "Notes").await;
        relay
            .ok(ALICE, "create_note", json!({ "path": "a.md", "content": "one two one" }))
            .await;

        for (tool, arguments) in [
            // Already there, in any letter case.
            ("create_note", json!({ "path": "A.md", "content": "" })),
            ("create_note", json!({ "path": "notes.txt", "content": "" })),
            ("create_note", json!({ "path": ".hidden/a.md", "content": "" })),
            ("create_note", json!({ "path": "../a.md", "content": "" })),
            // A note is not a folder.
            ("create_note", json!({ "path": "a.md/b.md", "content": "" })),
            ("read_note", json!({ "path": "missing.md" })),
            ("list_notes", json!({ "path": "missing" })),
            ("edit_note", json!({ "path": "a.md", "old_text": "three", "new_text": "3" })),
            // Two matches and no replace_all.
            ("edit_note", json!({ "path": "a.md", "old_text": "one", "new_text": "1" })),
            ("edit_note", json!({ "path": "a.md", "old_text": "", "new_text": "x" })),
            ("append_note", json!({ "path": "missing.md", "text": "x" })),
            ("read_note", json!({ "vault": "Other", "path": "a.md" })),
            ("search_notes", json!({ "query": "  " })),
        ] {
            relay.refused(ALICE, tool, arguments).await;
        }
        // None of that changed the note.
        assert_eq!(relay.ok(ALICE, "read_note", json!({ "path": "a.md" })).await, "one two one");

        relay
            .ok(
                ALICE,
                "edit_note",
                json!({ "path": "a.md", "old_text": "one", "new_text": "1", "replace_all": true }),
            )
            .await;
        assert_eq!(relay.ok(ALICE, "read_note", json!({ "path": "a.md" })).await, "1 two 1");

        // With a second vault, the vault has to be named.
        create_vault(&relay.base, ALICE, "Work").await;
        let why = relay.refused(ALICE, "read_note", json!({ "path": "a.md" })).await;
        assert!(why.contains("Notes") && why.contains("Work"), "{why}");
        relay.ok(ALICE, "read_note", json!({ "vault": "notes", "path": "a.md" })).await;
    }

    #[sqlx::test(migrations = false)]
    async fn tools_never_reach_another_members_notes(pool: PgPool) {
        let relay = start(&pool).await;
        create_vault(&relay.base, ALICE, "Notes").await;
        let (_, bobs) = create_vault(&relay.base, BOB, "Notes").await;
        relay
            .ok(ALICE, "create_note", json!({ "path": "secret.md", "content": "alice only" }))
            .await;

        // Same vault name, his own vault: hers is not in it.
        assert!(paths(&relay.ok(BOB, "list_notes", json!({ "recursive": true })).await).is_empty());
        relay.refused(BOB, "read_note", json!({ "path": "secret.md" })).await;
        assert!(paths(&relay.ok(BOB, "search_notes", json!({ "query": "alice" })).await).is_empty());

        // Bob writes a link to her note into his own root folder.
        let alice = auth::Did(ALICE.into());
        let notes = mcp::tests::notes_of(&relay.authz, &alice).await;
        let secret = notes.into_iter().find(|(path, _)| path == "secret.md").unwrap().1;
        let bobs_root: samod::DocumentId = bobs["root_doc_id"].as_str().unwrap().parse().unwrap();
        let entry = reach::Entry {
            name: "stolen.md".to_string(),
            kind: "md".to_string(),
            url: samod::AutomergeUrl::from(&secret).to_string(),
        };
        relay
            .repo
            .find(bobs_root)
            .await
            .unwrap()
            .unwrap()
            .with_document_async(move |doc| reach::add_entry(doc, &entry))
            .await
            .unwrap()
            .unwrap();

        assert!(paths(&relay.ok(BOB, "list_notes", json!({})).await).is_empty());
        relay.refused(BOB, "read_note", json!({ "path": "stolen.md" })).await;
        relay
            .refused(BOB, "append_note", json!({ "path": "stolen.md", "text": "mine now" }))
            .await;
        assert!(paths(&relay.ok(BOB, "search_notes", json!({ "query": "alice" })).await).is_empty());
        assert_eq!(
            relay.ok(ALICE, "read_note", json!({ "path": "secret.md" })).await,
            "alice only"
        );
    }

    #[sqlx::test(migrations = false)]
    async fn an_mcp_edit_reaches_a_sync_client_and_a_sync_edit_reaches_mcp(pool: PgPool) {
        use automerge::{transaction::Transactable, ReadDoc};

        let relay = start(&pool).await;
        let (_, vault) = create_vault(&relay.base, ALICE, "Notes").await;
        let root: samod::DocumentId = vault["root_doc_id"].as_str().unwrap().parse().unwrap();

        // Her device is connected and syncing the vault's root before
        // anything is written.
        let device = client(&relay.base, ALICE).await;
        let folder = device.find(root).await.unwrap().expect("the vault root");

        relay
            .ok(ALICE, "create_note", json!({ "path": "today.md", "content": "from Claude" }))
            .await;

        // The new entry arrives in the folder she already has...
        let mut entries = Vec::new();
        for _ in 0..100 {
            entries = folder
                .with_document_async(|doc| reach::read_entries(doc))
                .await
                .unwrap();
            if !entries.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(entries.len(), 1, "the entry never reached the device");
        assert_eq!((entries[0].name.as_str(), entries[0].kind.as_str()), ("today.md", "md"));

        // ...and the note it points at can be fetched, as the plugin would.
        let note_id = entries[0].doc_id().unwrap();
        let note = device.find(note_id).await.unwrap().expect("the note");
        let text = note
            .with_document_async(|doc| reach::read_string(doc, &automerge::ROOT, "content"))
            .await
            .unwrap();
        assert_eq!(text.as_deref(), Some("from Claude"));

        // She types on the device. MCP reads it with no laptop in between.
        note.with_document_async(|doc| {
            let (_, content) = doc.get(automerge::ROOT, "content").unwrap().unwrap();
            let end = doc.length(&content);
            let mut tx = doc.transaction();
            tx.splice_text(&content, end, 0, ", and from the phone").unwrap();
            tx.commit();
        })
        .await
        .unwrap();

        for _ in 0..100 {
            let text = relay.ok(ALICE, "read_note", json!({ "path": "today.md" })).await;
            if text == "from Claude, and from the phone" {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("the device's edit never reached MCP");
    }
}
