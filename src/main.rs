//! An Automerge sync relay for the Shared Computer Network.
//!
//! Speaks the automerge-repo WebSocket protocol via `samod`, and persists to
//! Postgres. A connection is authenticated as a member's DID before the
//! websocket upgrade; see `auth.rs` and [`build_verifier`].

mod auth;
mod config;
mod storage;

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
use samod::{AcceptorHandle, Repo};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;

use auth::{AllowAll, CorlissVerifier, DidVerifier, Verified};
use config::Config;
use storage::PostgresStorage;

#[derive(Clone)]
struct AppState {
    acceptor: AcceptorHandle,
    verifier: Arc<dyn DidVerifier>,
    /// The audience a sync token must carry. Empty when nothing is verified.
    sync_audience: Arc<str>,
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

    let store = PostgresStorage::new(pool);
    store
        .migrate()
        .await
        .context("could not create the storage schema")?;

    let repo = Repo::build_tokio().with_storage(store).load().await;

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
    });

    let listener = tokio::net::TcpListener::bind(&config.bind)
        .await
        .with_context(|| format!("could not bind {}", config.bind))?;

    tracing::info!(
        bind = %config.bind,
        auth = verifier.name(),
        "scn-sync-relay listening"
    );
    if !config.require_auth {
        tracing::warn!(
            "running WITHOUT a membership gate: any peer that can reach this \
             port can sync any document this relay holds. This is only sound \
             while the service has no route through the proxy."
        );
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
        .context("server error")?;

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
    // No expected peer ID: samod's peer ID is the client's own choice and says
    // nothing about who it is. The DID is what the connection is bound to.
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
    use serde_json::json;

    /// The relay's router on a loopback port, gated by a verifier that trusts
    /// the test issuer. The repo is samod's in-memory default.
    async fn relay() -> String {
        let issuer = Issuer::start().await;
        let repo = Repo::build_tokio().load().await;
        let acceptor = repo
            .make_acceptor("ws://relay.test/sync".parse().unwrap())
            .unwrap();
        let app = router(AppState {
            acceptor,
            verifier: Arc::new(issuer.verifier().await),
            sync_audience: SYNC_AUDIENCE.into(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
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

    #[tokio::test]
    async fn good_token_upgrades() {
        let base = relay().await;
        let token = TokenSpec::default().sign();
        for path in ["/", "/sync"] {
            let status = upgrade(&format!("{base}{path}?access_token={token}")).await;
            assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS, "{path}");
        }
    }

    #[tokio::test]
    async fn bad_or_missing_token_gets_401_before_upgrade() {
        let base = relay().await;
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
}
