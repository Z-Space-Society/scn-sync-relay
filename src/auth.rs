//! Who is on the other end of a connection.
//!
//! Two implementations sit behind one seam. [`CorlissVerifier`] checks an
//! access token issued by Corliss, the network's OAuth provider, and is what a
//! deployed relay runs. [`AllowAll`] is no verifier at all, for local work.
//!
//! A verifier for ATProto service auth can join them later: the client mints a
//! short-lived JWT with `com.atproto.server.getServiceAuth`, audience-bound to
//! this relay's service DID, and the relay verifies it by resolving the
//! caller's DID document. Everything past the verifier sees only a DID.
//!
//! The trait is written with boxed futures rather than `async fn` so it stays
//! object-safe: `main` holds an `Arc<dyn DidVerifier>`, so a new verifier is a
//! new type and one line of wiring, not a type parameter threaded through the
//! app.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An authenticated ATProto DID.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Did(pub String);

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The outcome of a successful check: who, and until when.
#[derive(Clone, Debug)]
pub struct Verified {
    pub did: Did,
    /// When the credential stops being good. A sync connection is closed at
    /// this moment, which is what cuts off a member who has left the network.
    /// `None` only from [`AllowAll`], which has no credential to expire.
    // Unread until the transport filter lands; it is the filter that closes
    // the socket.
    #[allow(dead_code)]
    pub expires_at: Option<SystemTime>,
}

#[derive(Debug)]
pub enum AuthError {
    /// No credential was presented at all.
    Missing,
    /// A credential was presented and did not check out. The string is for the
    /// log, never for the client: telling a caller *why* their token failed is
    /// how you build an oracle. It must never contain the token itself.
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
    ///
    /// The caller names the audience it expects, because sync and MCP are
    /// separate resources and a token for one must not open the other.
    fn verify<'a>(
        &'a self,
        token: Option<&'a str>,
        audience: &'a str,
    ) -> BoxFuture<'a, Result<Verified, AuthError>>;

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
/// one if it reaches an ownership check.
const ANONYMOUS: &str = "anonymous";

impl DidVerifier for AllowAll {
    fn verify<'a>(
        &'a self,
        _token: Option<&'a str>,
        _audience: &'a str,
    ) -> BoxFuture<'a, Result<Verified, AuthError>> {
        Box::pin(async {
            Ok(Verified {
                did: Did(ANONYMOUS.to_string()),
                expires_at: None,
            })
        })
    }

    fn name(&self) -> &'static str {
        "allow-all"
    }
}

/// The shortest gap between two JWKS fetches.
///
/// An unknown `kid` triggers a refetch so a key rotation is picked up without
/// a restart. Without a floor, anyone could make the relay hammer the issuer
/// by sending tokens with made-up key IDs.
const JWKS_REFETCH_FLOOR: Duration = Duration::from_secs(30);

const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Verifies access tokens issued by Corliss.
///
/// The token is an RS256 JWT whose `sub` is the member's DID and whose `aud`
/// is the one resource it was issued for. Corliss re-checks membership every
/// time it issues one, and they are short lived, so "holds a valid token" is
/// "was a member a few minutes ago".
pub struct CorlissVerifier {
    issuer: String,
    jwks_url: String,
    client: reqwest::Client,
    keys: RwLock<HashMap<String, DecodingKey>>,
    /// When the JWKS was last asked for, whether or not that worked. Held
    /// across the fetch, so a burst of tokens with one new `kid` costs one
    /// request.
    last_fetch: tokio::sync::Mutex<Option<Instant>>,
}

/// The claims the relay reads. `iss`, `aud` and `exp` are checked by the
/// library; the rest of the token is ignored.
#[derive(Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
}

impl CorlissVerifier {
    /// Build the verifier and load the issuer's keys.
    ///
    /// A failed first fetch is logged and not fatal. The relay and the issuer
    /// start independently, and refusing to boot would turn an issuer restart
    /// into a relay outage. Until a fetch succeeds every token is refused,
    /// which is the safe direction.
    pub async fn new(issuer: String, jwks_url: String) -> Result<Self> {
        // reqwest is built without a TLS provider of its own; this is the one
        // the rest of the binary already uses. An error means it was installed
        // already, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = reqwest::Client::builder()
            .timeout(JWKS_FETCH_TIMEOUT)
            .build()
            .context("could not build the HTTP client for the JWKS")?;

        let verifier = Self {
            issuer,
            jwks_url,
            client,
            keys: RwLock::new(HashMap::new()),
            last_fetch: tokio::sync::Mutex::new(None),
        };

        *verifier.last_fetch.lock().await = Some(Instant::now());
        if let Err(e) = verifier.fetch().await {
            tracing::warn!(
                jwks_url = %verifier.jwks_url,
                error = %e,
                "could not load the issuer's keys at startup; refusing every \
                 token until a fetch succeeds"
            );
        }
        Ok(verifier)
    }

    /// Replace the cached keys with the issuer's current set.
    async fn fetch(&self) -> Result<()> {
        let body: serde_json::Value = self
            .client
            .get(&self.jwks_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        // Read as loose JSON rather than a typed key set: the issuer publishes
        // keys of other types beside its RSA one, and one entry this build
        // cannot parse must not cost the whole document.
        let mut keys = HashMap::new();
        for jwk in body["keys"].as_array().into_iter().flatten() {
            let (Some("RSA"), Some(kid), Some(n), Some(e)) = (
                jwk["kty"].as_str(),
                jwk["kid"].as_str(),
                jwk["n"].as_str(),
                jwk["e"].as_str(),
            ) else {
                continue;
            };
            match DecodingKey::from_rsa_components(n, e) {
                Ok(key) => {
                    keys.insert(kid.to_string(), key);
                }
                Err(e) => tracing::warn!(kid, error = %e, "skipping an unusable RSA key"),
            }
        }
        anyhow::ensure!(!keys.is_empty(), "the JWKS holds no usable RSA key");

        *self.keys.write().unwrap() = keys;
        Ok(())
    }

    fn cached_key(&self, kid: &str) -> Option<DecodingKey> {
        self.keys.read().unwrap().get(kid).cloned()
    }

    /// Find the key for a `kid`, asking the issuer again if it is new to us.
    async fn key_for(&self, kid: &str) -> Option<DecodingKey> {
        if let Some(key) = self.cached_key(kid) {
            return Some(key);
        }

        let mut last_fetch = self.last_fetch.lock().await;
        // Another caller may have fetched while this one waited for the lock.
        if let Some(key) = self.cached_key(kid) {
            return Some(key);
        }
        if last_fetch.is_some_and(|at| at.elapsed() < JWKS_REFETCH_FLOOR) {
            return None;
        }
        *last_fetch = Some(Instant::now());
        if let Err(e) = self.fetch().await {
            tracing::warn!(jwks_url = %self.jwks_url, error = %e, "JWKS refetch failed");
        }
        self.cached_key(kid)
    }

    async fn check(&self, token: &str, audience: &str) -> Result<Verified, AuthError> {
        let invalid = |why: &str| AuthError::Invalid(why.to_string());

        let header = decode_header(token).map_err(|_| invalid("not a JWT"))?;
        if header.alg != Algorithm::RS256 {
            return Err(invalid("algorithm is not RS256"));
        }
        // RFC 9068: an access token says so in its header. This is what keeps
        // an ID token, signed by the same key, from being presented as one.
        let typ = header.typ.as_deref().unwrap_or_default();
        if !typ.eq_ignore_ascii_case("at+jwt") && !typ.eq_ignore_ascii_case("application/at+jwt") {
            return Err(invalid("not an access token"));
        }
        let kid = header.kid.ok_or_else(|| invalid("no key ID"))?;
        let key = self
            .key_for(&kid)
            .await
            .ok_or_else(|| invalid("unknown key ID"))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        // The relay closes a connection at `exp`, so `exp` is exact here too.
        validation.leeway = 0;

        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|e| AuthError::Invalid(e.to_string()))?
            .claims;

        if !is_did(&claims.sub) {
            return Err(invalid("subject is not a DID"));
        }

        Ok(Verified {
            did: Did(claims.sub),
            expires_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(claims.exp)),
        })
    }
}

/// `did:<method>:<identifier>`, the shape and nothing more. Whether the DID is
/// a member is the issuer's call, made when it signed the token.
pub fn is_did(s: &str) -> bool {
    let mut parts = s.splitn(3, ':');
    parts.next() == Some("did")
        && parts.next().is_some_and(|method| !method.is_empty())
        && parts.next().is_some_and(|id| !id.is_empty())
}

impl DidVerifier for CorlissVerifier {
    fn verify<'a>(
        &'a self,
        token: Option<&'a str>,
        audience: &'a str,
    ) -> BoxFuture<'a, Result<Verified, AuthError>> {
        Box::pin(async move {
            match token {
                Some(token) => self.check(token, audience).await,
                None => Err(AuthError::Missing),
            }
        })
    }

    fn name(&self) -> &'static str {
        "corliss"
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::{routing::get, Router};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    pub const ISSUER: &str = "https://corliss.test";
    pub const SYNC_AUDIENCE: &str = "https://sync.corliss.test";
    const MCP_AUDIENCE: &str = "https://mcp.corliss.test";
    const MEMBER: &str = "did:plc:alice";

    const TEST_KEY: &str = include_str!("../tests/fixtures/test-key.pem");
    const OTHER_KEY: &str = include_str!("../tests/fixtures/other-key.pem");
    const JWKS: &str = include_str!("../tests/fixtures/jwks.json");
    const JWKS_ROTATED: &str = include_str!("../tests/fixtures/jwks-rotated.json");

    fn now() -> u64 {
        jsonwebtoken::get_current_timestamp()
    }

    /// A token as Corliss issues it, with any claim or header overridden.
    pub struct TokenSpec {
        pub kid: &'static str,
        pub typ: &'static str,
        pub key: &'static str,
        pub claims: serde_json::Value,
    }

    impl Default for TokenSpec {
        fn default() -> Self {
            Self {
                kid: "test-key",
                typ: "at+jwt",
                key: TEST_KEY,
                claims: json!({
                    "iss": ISSUER,
                    "sub": MEMBER,
                    "aud": SYNC_AUDIENCE,
                    "iat": now(),
                    "exp": now() + 900,
                    "jti": "test",
                    "scope": "",
                    "client_id": "https://corliss.test/clients/scn-obsidian.json",
                }),
            }
        }
    }

    impl TokenSpec {
        pub fn claim(mut self, name: &str, value: serde_json::Value) -> Self {
            self.claims[name] = value;
            self
        }

        pub fn sign(&self) -> String {
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(self.kid.to_string());
            header.typ = Some(self.typ.to_string());
            let key = EncodingKey::from_rsa_pem(self.key.as_bytes()).unwrap();
            encode(&header, &self.claims, &key).unwrap()
        }
    }

    /// Serve a JWKS on a loopback port and count how often it is asked for.
    /// The body can be swapped, to stand in for a key rotation.
    pub struct Issuer {
        pub jwks_url: String,
        pub fetches: Arc<AtomicUsize>,
        body: Arc<RwLock<&'static str>>,
    }

    impl Issuer {
        pub async fn start() -> Self {
            let fetches = Arc::new(AtomicUsize::new(0));
            let body = Arc::new(RwLock::new(JWKS));
            let app = Router::new().route(
                "/jwks",
                get({
                    let fetches = Arc::clone(&fetches);
                    let body = Arc::clone(&body);
                    move || async move {
                        fetches.fetch_add(1, Ordering::SeqCst);
                        *body.read().unwrap()
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let jwks_url = format!("http://{}/jwks", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            Self {
                jwks_url,
                fetches,
                body,
            }
        }

        fn rotate(&self) {
            *self.body.write().unwrap() = JWKS_ROTATED;
        }

        pub async fn verifier(&self) -> CorlissVerifier {
            CorlissVerifier::new(ISSUER.to_string(), self.jwks_url.clone())
                .await
                .unwrap()
        }
    }

    async fn verify(spec: TokenSpec) -> Result<Verified, AuthError> {
        let issuer = Issuer::start().await;
        let verifier = issuer.verifier().await;
        verifier.verify(Some(&spec.sign()), SYNC_AUDIENCE).await
    }

    /// Let a refetch through without waiting out the floor.
    async fn expire_floor(verifier: &CorlissVerifier) {
        *verifier.last_fetch.lock().await = Instant::now().checked_sub(JWKS_REFETCH_FLOOR);
    }

    #[tokio::test]
    async fn good_token_resolves_to_its_did_and_expiry() {
        let spec = TokenSpec::default();
        let exp = spec.claims["exp"].as_u64().unwrap();
        let verified = verify(spec).await.unwrap();
        assert_eq!(verified.did, Did(MEMBER.to_string()));
        assert_eq!(
            verified.expires_at,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(exp))
        );
    }

    #[tokio::test]
    async fn missing_token_is_refused() {
        let issuer = Issuer::start().await;
        let verifier = issuer.verifier().await;
        let result = verifier.verify(None, SYNC_AUDIENCE).await;
        assert!(matches!(result, Err(AuthError::Missing)));
    }

    #[tokio::test]
    async fn expired_token_is_refused() {
        let spec = TokenSpec::default().claim("exp", json!(now() - 1));
        assert!(matches!(verify(spec).await, Err(AuthError::Invalid(_))));
    }

    #[tokio::test]
    async fn token_for_another_audience_is_refused() {
        let spec = TokenSpec::default().claim("aud", json!(MCP_AUDIENCE));
        assert!(matches!(verify(spec).await, Err(AuthError::Invalid(_))));
    }

    #[tokio::test]
    async fn token_from_another_issuer_is_refused() {
        let spec = TokenSpec::default().claim("iss", json!("https://elsewhere.test"));
        assert!(matches!(verify(spec).await, Err(AuthError::Invalid(_))));
    }

    #[tokio::test]
    async fn subject_that_is_not_a_did_is_refused() {
        for sub in ["alice", "did:plc:", "did::alice", ""] {
            let spec = TokenSpec::default().claim("sub", json!(sub));
            assert!(
                matches!(verify(spec).await, Err(AuthError::Invalid(_))),
                "{sub:?}"
            );
        }
    }

    #[tokio::test]
    async fn id_token_is_refused() {
        let spec = TokenSpec {
            typ: "JWT",
            ..TokenSpec::default()
        };
        assert!(matches!(verify(spec).await, Err(AuthError::Invalid(_))));
    }

    #[tokio::test]
    async fn token_signed_by_another_key_is_refused() {
        let spec = TokenSpec {
            key: OTHER_KEY,
            ..TokenSpec::default()
        };
        assert!(matches!(verify(spec).await, Err(AuthError::Invalid(_))));
    }

    #[tokio::test]
    async fn algorithm_other_than_rs256_is_refused() {
        let issuer = Issuer::start().await;
        let verifier = issuer.verifier().await;
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key".to_string());
        header.typ = Some("at+jwt".to_string());
        let token = encode(
            &header,
            &TokenSpec::default().claims,
            &EncodingKey::from_secret(b"not the issuer"),
        )
        .unwrap();
        let result = verifier.verify(Some(&token), SYNC_AUDIENCE).await;
        assert!(matches!(result, Err(AuthError::Invalid(_))));
    }

    #[tokio::test]
    async fn garbage_is_refused() {
        let issuer = Issuer::start().await;
        let verifier = issuer.verifier().await;
        let result = verifier.verify(Some("not.a.token"), SYNC_AUDIENCE).await;
        assert!(matches!(result, Err(AuthError::Invalid(_))));
    }

    #[tokio::test]
    async fn known_key_costs_no_refetch() {
        let issuer = Issuer::start().await;
        let verifier = issuer.verifier().await;
        let token = TokenSpec::default().sign();
        for _ in 0..3 {
            verifier.verify(Some(&token), SYNC_AUDIENCE).await.unwrap();
        }
        assert_eq!(issuer.fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unknown_key_triggers_one_refetch() {
        let issuer = Issuer::start().await;
        let verifier = issuer.verifier().await;
        let rotated = TokenSpec {
            kid: "rotated-key",
            key: OTHER_KEY,
            ..TokenSpec::default()
        }
        .sign();

        // Inside the floor: refused without asking the issuer again.
        issuer.rotate();
        let result = verifier.verify(Some(&rotated), SYNC_AUDIENCE).await;
        assert!(matches!(result, Err(AuthError::Invalid(_))));
        assert_eq!(issuer.fetches.load(Ordering::SeqCst), 1);

        // Past the floor: one refetch finds the new key, and it stays cached.
        expire_floor(&verifier).await;
        verifier.verify(Some(&rotated), SYNC_AUDIENCE).await.unwrap();
        verifier.verify(Some(&rotated), SYNC_AUDIENCE).await.unwrap();
        assert_eq!(issuer.fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn issuer_down_at_startup_refuses_then_recovers() {
        let issuer = Issuer::start().await;
        let verifier = CorlissVerifier::new(
            ISSUER.to_string(),
            issuer.jwks_url.replace("/jwks", "/missing"),
        )
        .await
        .unwrap();
        let token = TokenSpec::default().sign();
        let result = verifier.verify(Some(&token), SYNC_AUDIENCE).await;
        assert!(matches!(result, Err(AuthError::Invalid(_))));

        let verifier = CorlissVerifier {
            jwks_url: issuer.jwks_url.clone(),
            ..verifier
        };
        expire_floor(&verifier).await;
        verifier.verify(Some(&token), SYNC_AUDIENCE).await.unwrap();
    }
}
