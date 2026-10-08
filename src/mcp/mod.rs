//! The MCP service: a member's notes, for an MCP client acting as that member.
//!
//! Same process and same repo as sync. A tool reads and edits the documents
//! the relay already holds, and an edit reaches connected devices through
//! samod's ordinary sync.
//!
//! It is stateless. No session is issued, each request carries its own token,
//! and a tool call returns one JSON body. A relay restart therefore needs
//! nothing from the client.

mod notes;
mod search;
mod tools;

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use serde_json::json;

use crate::auth::DidVerifier;
use crate::authz::Authz;

const METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

#[derive(Clone)]
struct McpState {
    verifier: Arc<dyn DidVerifier>,
    /// The public MCP URL: the audience a token must carry and the `resource`
    /// the metadata names.
    audience: Arc<str>,
    issuer: Arc<str>,
    /// Where an unauthenticated client is sent to find the issuer.
    metadata_url: Arc<str>,
}

/// Build the MCP listener's routes.
///
/// `audience` is the public MCP URL. Its host is the only `Host` the service
/// answers to, and its path is where the service is mounted.
pub fn router(
    authz: Authz,
    verifier: Arc<dyn DidVerifier>,
    audience: &str,
    issuer: &str,
) -> Result<Router> {
    let url: samod::Url = audience
        .parse()
        .context("the MCP audience is not a valid URL")?;
    let host = url.host_str().context("the MCP audience has no host")?;
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let path = url.path().trim_end_matches('/');
    let origin = format!("{}://{authority}", url.scheme());

    let state = McpState {
        verifier,
        audience: audience.into(),
        issuer: issuer.into(),
        // The metadata path carries the MCP path as a suffix.
        metadata_url: format!("{origin}{METADATA_PATH}{path}").into(),
    };

    let service: StreamableHttpService<tools::NotesServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(tools::NotesServer::new(authz.clone())),
            Default::default(),
            StreamableHttpServerConfig::default()
                // rmcp answers only loopback hosts unless told otherwise.
                .with_allowed_hosts([authority])
                .with_legacy_session_mode(false)
                .with_json_response(true),
        );
    let protected = if path.is_empty() {
        Router::new().fallback_service(service)
    } else {
        Router::new().nest_service(path, service)
    }
    .layer(middleware::from_fn_with_state(state.clone(), authenticate));

    let mut open = Router::new().route(METADATA_PATH, get(metadata));
    if !path.is_empty() {
        open = open.route(&format!("{METADATA_PATH}{path}"), get(metadata));
    }
    Ok(open.with_state(state).merge(protected))
}

/// RFC 9728 protected resource metadata: which authorization server issues
/// tokens for this resource. It is how an MCP client finds Corliss.
async fn metadata(State(state): State<McpState>) -> impl IntoResponse {
    Json(json!({
        "resource": &*state.audience,
        "authorization_servers": [&*state.issuer],
        "bearer_methods_supported": ["header"],
    }))
}

/// Verify the bearer token and leave the member's DID where tools find it.
async fn authenticate(State(state): State<McpState>, mut request: Request, next: Next) -> Response {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim().to_string());

    match state.verifier.verify(token.as_deref(), &state.audience).await {
        Ok(verified) => {
            request.extensions_mut().insert(verified.did);
            next.run(request).await
        }
        Err(e) => {
            tracing::info!(error = %e, "refused an MCP request");
            let challenge = format!("Bearer resource_metadata=\"{}\"", state.metadata_url);
            let mut response = (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
            if let Ok(value) = HeaderValue::from_str(&challenge) {
                response.headers_mut().insert(header::WWW_AUTHENTICATE, value);
            }
            response
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use samod::DocumentId;

    use crate::auth::Did;
    use crate::authz::Authz;

    /// Every note in a member's only vault, as path and document ID.
    pub async fn notes_of(authz: &Authz, did: &Did) -> Vec<(String, DocumentId)> {
        let notes = super::notes::Notes { authz, did };
        let (root, _) = notes.vault(None).await.unwrap();
        notes
            .list(&root, "", true)
            .await
            .unwrap()
            .into_iter()
            .filter(|found| !found.is_folder)
            .map(|found| (found.path, found.id))
            .collect()
    }
}
