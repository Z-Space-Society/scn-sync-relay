//! Runtime configuration, read from the environment.
//!
//! Every setting arrives as an environment variable because that is what the
//! deployment gives us: Ansible renders an `EnvironmentFile` that systemd loads
//! into the unit. There is no config file to keep in sync with the role.

use anyhow::{Context, Result};

/// Prefix for every variable this service reads, so nothing it looks at can
/// collide with something else on the host.
const PREFIX: &str = "SCN_SYNC_RELAY_";

pub struct Config {
    /// Postgres connection string. The only setting with no default: a relay
    /// that silently fell back to in-memory storage would look healthy right up
    /// until a restart lost every document.
    pub database_url: String,

    /// Address to bind. Must be a wildcard, not the container's own address —
    /// binding a literal `10.1.1.x` loses a cold-boot race with
    /// systemd-networkd and comes up silently loopback-only.
    pub bind: String,

    /// Whether a connection must present a verified DID.
    ///
    /// Defaults to **true**, so the safe posture is the one you get by
    /// forgetting to set it. Phase A deployments set it to false explicitly,
    /// which is the point: running without a membership gate is a decision
    /// someone has to write down.
    pub require_auth: bool,

    /// What the token verifier needs. Present exactly when `require_auth` is
    /// on, so a gated relay cannot start half configured.
    pub auth: Option<AuthConfig>,
}

pub struct AuthConfig {
    /// The `iss` every token must carry: the issuer's public URL.
    pub oidc_issuer: String,

    /// Where to fetch the issuer's signing keys. Separate from the issuer
    /// because the relay reaches it over the internal network, not the public
    /// name.
    pub oidc_jwks_url: String,

    /// The `aud` a sync token must carry: this relay's public sync URL,
    /// spelled exactly as the issuer spells it.
    pub sync_audience: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let database_url = var("DATABASE_URL").with_context(|| {
            format!("{PREFIX}DATABASE_URL must be set — there is no in-memory fallback")
        })?;

        let bind = var("BIND").unwrap_or_else(|_| "0.0.0.0:7030".to_string());

        // Anything that isn't an explicit, recognised "off" leaves the gate on.
        let require_auth = match var("REQUIRE_AUTH") {
            Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no"),
            Err(_) => true,
        };

        let auth = if require_auth {
            Some(AuthConfig {
                oidc_issuer: required_for_auth("OIDC_ISSUER")?,
                oidc_jwks_url: required_for_auth("OIDC_JWKS_URL")?,
                sync_audience: required_for_auth("SYNC_AUDIENCE")?,
            })
        } else {
            None
        };

        Ok(Self {
            database_url,
            bind,
            require_auth,
            auth,
        })
    }
}

/// A setting the gated relay cannot run without. Blank counts as missing: an
/// empty audience or issuer would be compared against tokens as if it meant
/// something.
fn required_for_auth(name: &str) -> Result<String> {
    match var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => anyhow::bail!(
            "{PREFIX}{name} must be set when {PREFIX}REQUIRE_AUTH is on. Set \
             {PREFIX}REQUIRE_AUTH=false to run the unauthenticated relay, and \
             only where it has no route in."
        ),
    }
}

fn var(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(format!("{PREFIX}{name}"))
}
