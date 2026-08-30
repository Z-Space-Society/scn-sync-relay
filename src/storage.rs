//! A Postgres [`Storage`] implementation for samod.
//!
//! samod ships `InMemoryStorage` and `TokioFilesystemStorage`; neither is the
//! store of record we want. The trait is a key/value store with range queries,
//! which is a two-column table with a prefix index — and Postgres additionally
//! gives us transactional compaction later (swapping change records for a
//! compacted blob atomically, with no crash window) and one backup story shared
//! with every other service on the cluster.
//!
//! **Key encoding.** `StorageKey` guarantees no component contains a `/`, which
//! the trait's own documentation calls out as licence to join components with
//! `/` when storing a key as a string. So the round trip is exactly
//! `Display` out and `split('/')` back, with no escaping and no ambiguity.

use std::collections::HashMap;

use samod::storage::{Storage, StorageKey};
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create the table if it isn't there yet.
    ///
    /// The Ansible role creates the database and the role that owns it, but not
    /// the schema — every app here runs its own migrations. At one table this
    /// is cheaper and more legible than a migration framework, and it stays
    /// idempotent across replays.
    ///
    /// `text_pattern_ops` is the load-bearing part of the index: the default
    /// opclass follows the database's collation and will *not* be used for a
    /// `LIKE 'prefix%'` scan, so `load_range` would silently become a full
    /// table scan on a table that only grows.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS storage (
                 key   TEXT  PRIMARY KEY,
                 value BYTEA NOT NULL
             )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS storage_key_prefix
                 ON storage (key text_pattern_ops)",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// `StorageKey` → the stored string form.
fn encode(key: &StorageKey) -> String {
    key.to_string()
}

/// The stored string form → `StorageKey`.
///
/// Returns `None` for a row we cannot parse rather than propagating an error:
/// the caller is a trait method with no error channel, and a single unreadable
/// row should cost that row, not the whole range query.
fn decode(raw: &str) -> Option<StorageKey> {
    StorageKey::from_parts(raw.split('/')).ok()
}

impl Storage for PostgresStorage {
    async fn load(&self, key: StorageKey) -> Option<Vec<u8>> {
        let encoded = encode(&key);
        let row = sqlx::query("SELECT value FROM storage WHERE key = $1")
            .bind(&encoded)
            .fetch_optional(&self.pool)
            .await;

        match row {
            Ok(Some(row)) => row.try_get::<Vec<u8>, _>("value").ok(),
            Ok(None) => None,
            Err(e) => {
                // A read failure and a genuine miss are indistinguishable to
                // samod, so log loudly: this is the shape of error that
                // otherwise presents as "the document is empty".
                tracing::error!(key = %encoded, error = %e, "storage load failed");
                None
            }
        }
    }

    async fn load_range(&self, prefix: StorageKey) -> HashMap<StorageKey, Vec<u8>> {
        let encoded = encode(&prefix);

        // An empty prefix means the whole store. Falling through to the LIKE
        // branch would build `'/%'` and match nothing, which reads as an empty
        // database rather than as a bug.
        let rows = if encoded.is_empty() {
            sqlx::query("SELECT key, value FROM storage")
                .fetch_all(&self.pool)
                .await
        } else {
            // Strictly below the prefix, matching the filesystem
            // implementation, which walks the directory *under* the prefix and
            // does not include the prefix itself.
            sqlx::query("SELECT key, value FROM storage WHERE key LIKE $1 || '/%'")
                .bind(&encoded)
                .fetch_all(&self.pool)
                .await
        };

        let rows = match rows {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(prefix = %encoded, error = %e, "storage load_range failed");
                return HashMap::new();
            }
        };

        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let Ok(raw) = row.try_get::<String, _>("key") else {
                continue;
            };
            let Ok(value) = row.try_get::<Vec<u8>, _>("value") else {
                continue;
            };
            let Some(key) = decode(&raw) else {
                tracing::warn!(key = %raw, "skipping unparseable storage key");
                continue;
            };
            out.insert(key, value);
        }
        out
    }

    async fn put(&self, key: StorageKey, data: Vec<u8>) {
        let encoded = encode(&key);
        // Upsert: samod re-puts the same key as a document's snapshot is
        // recompacted, and the trait gives us no way to signal a conflict.
        let result = sqlx::query(
            "INSERT INTO storage (key, value) VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&encoded)
        .bind(&data)
        .execute(&self.pool)
        .await;

        if let Err(e) = result {
            // The trait returns (), so a failed write cannot be reported
            // upward. This log is the only evidence, and a relay that cannot
            // write is a relay quietly losing changes — worth alerting on.
            tracing::error!(key = %encoded, error = %e, "storage put failed");
        }
    }

    async fn delete(&self, key: StorageKey) {
        let encoded = encode(&key);
        if let Err(e) = sqlx::query("DELETE FROM storage WHERE key = $1")
            .bind(&encoded)
            .execute(&self.pool)
            .await
        {
            tracing::error!(key = %encoded, error = %e, "storage delete failed");
        }
    }
}
