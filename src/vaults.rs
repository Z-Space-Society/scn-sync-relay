//! The vault endpoints.
//!
//! `GET /vaults` is for a member, who presents the same token as for sync and
//! sees their own vaults. The two `/internal/vaults` endpoints are for Corliss,
//! which lists and creates vaults on a member's behalf and presents a shared
//! service credential. The `/internal/` prefix exists so the proxy can leave it
//! unrouted: it is reachable on the internal network only.
//!
//! Vaults are created here and nowhere else. No sync client makes one.

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::auth::{is_did, Did};
use crate::authz::CreateVaultError;
use crate::AppState;

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token.trim())
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response()
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

fn internal_error(e: anyhow::Error) -> Response {
    tracing::error!(error = %e, "vault request failed");
    error(StatusCode::INTERNAL_SERVER_ERROR, "internal")
}

/// Is this call from Corliss? With no credential configured, nothing is.
fn is_service(state: &AppState, headers: &HeaderMap) -> bool {
    match (&state.service_token, bearer(headers)) {
        (Some(expected), Some(presented)) => {
            presented.as_bytes().ct_eq(expected.as_bytes()).into()
        }
        _ => false,
    }
}

async fn list(state: &AppState, did: &Did) -> Response {
    match state.authz.list_vaults(did).await {
        Ok(vaults) => Json(json!({ "vaults": vaults })).into_response(),
        Err(e) => internal_error(e),
    }
}

/// `GET /vaults`: the caller's own vaults.
pub async fn list_own(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let verified = match state
        .verifier
        .verify(bearer(&headers), &state.sync_audience)
        .await
    {
        Ok(verified) => verified,
        Err(e) => {
            tracing::info!(error = %e, "refused a vault listing");
            return unauthorized();
        }
    };
    list(&state, &verified.did).await
}

#[derive(Deserialize)]
pub struct ForMember {
    did: String,
}

/// `GET /internal/vaults?did=`: a member's vaults, for Corliss.
pub async fn list_for_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ForMember>,
) -> Response {
    if !is_service(&state, &headers) {
        return unauthorized();
    }
    if !is_did(&query.did) {
        return error(StatusCode::BAD_REQUEST, "invalid_did");
    }
    list(&state, &Did(query.did)).await
}

#[derive(Deserialize)]
pub struct NewVault {
    did: String,
    name: String,
}

/// `POST /internal/vaults`: create a vault for a member, for Corliss.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NewVault>,
) -> Response {
    if !is_service(&state, &headers) {
        return unauthorized();
    }
    if !is_did(&body.did) {
        return error(StatusCode::BAD_REQUEST, "invalid_did");
    }
    match state.authz.create_vault(&Did(body.did), &body.name).await {
        Ok(vault) => (StatusCode::CREATED, Json(vault)).into_response(),
        Err(CreateVaultError::InvalidName) => error(StatusCode::BAD_REQUEST, "invalid_name"),
        Err(CreateVaultError::NameTaken) => error(StatusCode::CONFLICT, "name_taken"),
        Err(CreateVaultError::Internal(e)) => internal_error(e),
    }
}
