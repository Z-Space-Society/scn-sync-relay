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

        Ok(Self {
            database_url,
            bind,
            require_auth,
        })
    }
}

fn var(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(format!("{PREFIX}{name}"))
}
