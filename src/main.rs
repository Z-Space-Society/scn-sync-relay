//! An Automerge sync relay for the Shared Computer Network.
//!
//! Speaks the automerge-repo WebSocket protocol via `samod`, and persists to
//! Postgres. Phase A: no membership enforcement — see `auth.rs` and the
//! startup refusal in [`build_verifier`].

mod auth;
mod config;
mod storage;

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use samod::{AcceptorHandle, Repo};
use sqlx::postgres::PgPoolOptions;

use auth::{AllowAll, DidVerifier};
use config::Config;
use storage::PostgresStorage;

#[derive(Clone)]
struct AppState {
    acceptor: AcceptorHandle,
    verifier: Arc<dyn DidVerifier>,
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
    let verifier = build_verifier(&config)?;

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

    let app = Router::new()
        // The websocket lives at BOTH the root and /sync, and the root is the one
        // that matters. `automerge-repo`'s WebSocketClientAdapter connects to
        // exactly the URL it is given and appends no path, and the reference
        // sync server serves at the root — so clients are configured with a bare
        // `ws://host:port`. Serving only /sync means a stock client gets a 404
        // instead of an upgrade, which surfaces as "sync silently never works".
        .route("/", get(sync))
        .route("/sync", get(sync))
        .route("/health", get(health))
        .with_state(AppState {
            acceptor,
            verifier: Arc::clone(&verifier),
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

/// Pick the verifier, or refuse to start.
///
/// Fails closed on purpose. `require_auth` defaults to true, and Phase A has no
/// verifier that can honour it, so the *only* way to run this build is to say
/// out loud that you want the ungated relay. When Phase B lands, this function
/// grows a second arm and the refusal disappears on its own.
fn build_verifier(config: &Config) -> Result<Arc<dyn DidVerifier>> {
    if config.require_auth {
        anyhow::bail!(
            "SCN_SYNC_RELAY_REQUIRE_AUTH is on, but this build has no DID verifier \
             (service auth is Phase B). Set SCN_SYNC_RELAY_REQUIRE_AUTH=false to run \
             the unauthenticated Phase A relay, and only where it has no route in."
        );
    }
    Ok(Arc::new(AllowAll))
}

/// Liveness only. It reports that the process is up and which auth mode it is
/// in; it deliberately does not touch Postgres, so a database blip cannot get
/// the relay restarted out from under live connections.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, format!("ok auth={}\n", state.verifier.name()))
}

async fn sync(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    // Authentication happens *before* the upgrade, so a rejected peer gets an
    // HTTP status it can act on rather than a socket that opens and then dies.
    //
    // Phase A note: the automerge-repo client has no way to send an
    // Authorization header on a browser WebSocket, so Phase B will need to
    // carry the token in the URL. Left unread here rather than guessed at.
    let did = match state.verifier.verify(None).await {
        Ok(did) => did,
        Err(e) => {
            tracing::info!(error = %e, "refused a connection");
            return (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
        }
    };

    ws.on_upgrade(move |socket| handle_socket(socket, state, did.to_string()))
        .into_response()
}

async fn handle_socket(socket: WebSocket, state: AppState, did: String) {
    match state.acceptor.accept_axum(socket) {
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
