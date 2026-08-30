//! Who is on the other end of a connection.
//!
//! Phase A ships one implementation, [`AllowAll`], and the seam it plugs into.
//! Phase B adds a verifier for ATProto service auth: the client mints a
//! short-lived JWT with `com.atproto.server.getServiceAuth`, audience-bound to
//! this relay's service DID, and the relay verifies it by resolving the
//! caller's DID document.
//!
//! The trait is written with boxed futures rather than `async fn` so it stays
//! object-safe. That is the whole reason it exists this early: `main` holds an
//! `Arc<dyn DidVerifier>`, so Phase B adds a file and changes one line of
//! wiring instead of threading a new type parameter through the app.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An authenticated ATProto DID.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Did(pub String);

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// Unconstructed in Phase A: `AllowAll` never rejects. These are the variants
// the service-auth verifier will return, kept here so the seam is complete and
// `sync()`'s rejection path is exercised by the type checker today.
#[allow(dead_code)]
#[derive(Debug)]
pub enum AuthError {
    /// No credential was presented at all.
    Missing,
    /// A credential was presented and did not check out. The string is for the
    /// log, never for the client: telling a caller *why* their token failed is
    /// how you build an oracle.
    Invalid(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Missing => write!(f, "no credential presented"),
            AuthError::Invalid(why) => write!(f, "invalid credential: {why}"),
        }
    }
}

pub trait DidVerifier: Send + Sync + 'static {
    /// Resolve a presented bearer token to a DID.
    fn verify<'a>(&'a self, token: Option<&'a str>) -> BoxFuture<'a, Result<Did, AuthError>>;

    /// A short name for logs and the health endpoint, so which mode a running
    /// relay is in is answerable without reading its unit file.
    fn name(&self) -> &'static str;
}

/// Accepts every connection as the same anonymous DID.
///
/// This is not a degraded verifier, it is *no* verifier: a relay running this
/// will sync any document id it holds to anyone who can reach the port. It is
/// only sound while the service has no route through the proxy and holds
/// nothing real. `main` refuses to select it unless the operator has explicitly
/// set `SCN_SYNC_RELAY_REQUIRE_AUTH=false`.
pub struct AllowAll;

/// Deliberately not a syntactically valid DID, so it can never be mistaken for
/// one if it reaches a membership check during Phase B development.
const ANONYMOUS: &str = "anonymous";

impl DidVerifier for AllowAll {
    fn verify<'a>(&'a self, _token: Option<&'a str>) -> BoxFuture<'a, Result<Did, AuthError>> {
        Box::pin(async { Ok(Did(ANONYMOUS.to_string())) })
    }

    fn name(&self) -> &'static str {
        "allow-all"
    }
}
