//! Who may open which document.
//!
//! Every check goes through [`Authz::may_open`]: the sync filter in both
//! directions and every MCP tool. Today the answer is owner-only. When sharing
//! arrives, the backing of that one function changes and nothing else does.
//!
//! Two records back it, in two tables beside `storage`:
//!
//! - `vaults`: one row per vault, naming its owner and its root folder document.
//! - `doc_creators`: the DID of whoever first sent each document.
//!
//! `doc_creators` is loaded into memory at startup and written through, and
//! the set of documents reachable from each vault's root is derived from it and
//! held in memory too (`reach.rs`). So `may_open` never touches the database,
//! which matters because it runs on every frame.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use samod::{AutomergeUrl, DocumentId, Repo};
use serde::Serialize;
use sqlx::{PgPool, Row};

use crate::auth::Did;
use crate::reach;

#[derive(Clone)]
pub struct Authz(pub(crate) Arc<Inner>);

pub(crate) struct Inner {
    pub(crate) pool: PgPool,
    pub(crate) repo: Repo,
    pub(crate) creators: RwLock<HashMap<DocumentId, Did>>,
    pub(crate) reach: RwLock<reach::Index>,
}

/// A vault as the endpoints return it.
#[derive(Clone, Debug, Serialize)]
pub struct Vault {
    pub root_doc_id: String,
    pub url: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_change_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub enum CreateVaultError {
    /// The name is empty or too long once trimmed.
    InvalidName,
    /// This owner already has a vault with that name, in any letter case.
    NameTaken,
    Internal(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for CreateVaultError {
    fn from(e: E) -> Self {
        CreateVaultError::Internal(e.into())
    }
}

/// The longest vault name, in characters, after trimming.
const MAX_VAULT_NAME: usize = 100;

impl Authz {
    /// Create the tables if needed, load the records, and start indexing.
    ///
    /// The reachability index fills in behind this call, one vault at a time.
    /// That is safe to serve through: until a vault is indexed its documents
    /// are still open to their creator, who is its owner, and to nobody else.
    pub async fn load(pool: PgPool, repo: Repo) -> Result<Self> {
        migrate(&pool)
            .await
            .context("could not create the ownership schema")?;

        let mut creators = HashMap::new();
        for row in sqlx::query("SELECT doc_id, creator_did FROM doc_creators")
            .fetch_all(&pool)
            .await?
        {
            let doc_id: String = row.try_get("doc_id")?;
            match DocumentId::from_str(&doc_id) {
                Ok(id) => {
                    creators.insert(id, Did(row.try_get("creator_did")?));
                }
                Err(_) => tracing::warn!(%doc_id, "skipping an unparseable document ID"),
            }
        }

        let authz = Self(Arc::new(Inner {
            pool,
            repo,
            creators: RwLock::new(creators),
            reach: RwLock::new(reach::Index::default()),
        }));

        for row in sqlx::query("SELECT root_doc_id, owner_did, last_change_at FROM vaults")
            .fetch_all(&authz.0.pool)
            .await?
        {
            let root: String = row.try_get("root_doc_id")?;
            match DocumentId::from_str(&root) {
                Ok(id) => authz.start_vault(
                    id,
                    Did(row.try_get("owner_did")?),
                    row.try_get("last_change_at")?,
                ),
                Err(_) => tracing::warn!(%root, "skipping a vault with an unparseable root"),
            }
        }
        authz.start_last_change_flush();

        Ok(authz)
    }

    /// May this DID open this document?
    ///
    /// Yes when the document is reachable from a vault the DID owns, or when
    /// the DID created it and no vault reaches it. The second case is a note
    /// not yet linked into a folder, one part way through a move, or one whose
    /// entry was deleted.
    // Called by the transport filter and the MCP tools, which are not built yet.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn may_open(&self, did: &Did, doc: &DocumentId) -> bool {
        if let Some(owner) = self.0.reach.read().unwrap().owner_of(doc) {
            return owner == did;
        }
        self.0.creators.read().unwrap().get(doc) == Some(did)
    }

    pub(crate) fn creator_of(&self, doc: &DocumentId) -> Option<Did> {
        self.0.creators.read().unwrap().get(doc).cloned()
    }

    /// Record who first sent a document, and return who that turned out to be.
    ///
    /// The first writer wins and the row is never changed, so two peers racing
    /// on one ID cannot both become its creator. Only a document's first frame
    /// reaches the database; after that the answer comes from memory.
    pub async fn record_creator(&self, doc: &DocumentId, did: &Did) -> Result<Did> {
        if let Some(creator) = self.creator_of(doc) {
            return Ok(creator);
        }

        let doc_id = doc.to_string();
        sqlx::query(
            "INSERT INTO doc_creators (doc_id, creator_did) VALUES ($1, $2)
             ON CONFLICT (doc_id) DO NOTHING",
        )
        .bind(&doc_id)
        .bind(&did.0)
        .execute(&self.0.pool)
        .await?;
        let creator = Did(
            sqlx::query("SELECT creator_did FROM doc_creators WHERE doc_id = $1")
                .bind(&doc_id)
                .fetch_one(&self.0.pool)
                .await?
                .try_get("creator_did")?,
        );

        self.0
            .creators
            .write()
            .unwrap()
            .insert(doc.clone(), creator.clone());
        // A folder may already link to this document, waiting to learn whose
        // it is.
        self.0.reach.read().unwrap().wake_pending(doc);
        Ok(creator)
    }

    /// The vaults a DID owns, oldest first.
    pub async fn list_vaults(&self, owner: &Did) -> Result<Vec<Vault>> {
        let rows = sqlx::query(
            "SELECT root_doc_id, name, created_at, last_change_at FROM vaults
             WHERE owner_did = $1 ORDER BY created_at, root_doc_id",
        )
        .bind(&owner.0)
        .fetch_all(&self.0.pool)
        .await?;

        let reach = self.0.reach.read().unwrap();
        let mut vaults = Vec::with_capacity(rows.len());
        for row in rows {
            let root: String = row.try_get("root_doc_id")?;
            // Memory is ahead of the table by up to a minute.
            let in_memory = DocumentId::from_str(&root)
                .ok()
                .and_then(|id| reach.last_change(&id));
            vaults.push(Vault {
                url: format!("automerge:{root}"),
                root_doc_id: root,
                name: row.try_get("name")?,
                created_at: row.try_get("created_at")?,
                last_change_at: in_memory.or(row.try_get("last_change_at")?),
            });
        }
        Ok(vaults)
    }

    /// Create a vault for a member: an empty root folder document and its row.
    ///
    /// Membership is not checked. The caller is Corliss, acting for a member
    /// who is signed in, and a vault whose owner cannot get a token is
    /// unreachable anyway.
    pub async fn create_vault(&self, owner: &Did, name: &str) -> Result<Vault, CreateVaultError> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_VAULT_NAME {
            return Err(CreateVaultError::InvalidName);
        }

        // Asked first so the ordinary duplicate leaves no document behind. The
        // unique index below is what makes it true under a race.
        let taken = sqlx::query(
            "SELECT 1 FROM vaults WHERE owner_did = $1 AND lower(name) = lower($2)",
        )
        .bind(&owner.0)
        .bind(name)
        .fetch_optional(&self.0.pool)
        .await?;
        if taken.is_some() {
            return Err(CreateVaultError::NameTaken);
        }

        let handle = self
            .0
            .repo
            .create(reach::new_folder(name)?)
            .await
            .map_err(|_| anyhow::anyhow!("repo stopped"))?;
        let root = handle.document_id().clone();
        self.record_creator(&root, owner).await?;

        let inserted = sqlx::query(
            "INSERT INTO vaults (root_doc_id, owner_did, name) VALUES ($1, $2, $3)
             RETURNING created_at",
        )
        .bind(root.to_string())
        .bind(&owner.0)
        .bind(name)
        .fetch_one(&self.0.pool)
        .await;
        let created_at = match inserted {
            Ok(row) => row.try_get("created_at")?,
            // Lost a race on the name. The root document stays behind, open
            // only to its creator and linked from nowhere.
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(CreateVaultError::NameTaken);
            }
            Err(e) => return Err(e.into()),
        };

        self.start_vault(root.clone(), owner.clone(), None);

        Ok(Vault {
            url: AutomergeUrl::from(&root).to_string(),
            root_doc_id: root.to_string(),
            name: name.to_string(),
            created_at,
            last_change_at: None,
        })
    }
}

/// Same approach as `PostgresStorage::migrate`: idempotent statements at
/// startup, no migration framework.
async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    for statement in [
        "CREATE TABLE IF NOT EXISTS vaults (
             root_doc_id    TEXT PRIMARY KEY,
             owner_did      TEXT NOT NULL,
             name           TEXT NOT NULL,
             created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
             last_change_at TIMESTAMPTZ
         )",
        // One name per owner whatever its letter case: tools address a note by
        // vault name and path. Also serves the lookup by owner.
        "CREATE UNIQUE INDEX IF NOT EXISTS vaults_owner_name
             ON vaults (owner_did, lower(name))",
        "CREATE TABLE IF NOT EXISTS doc_creators (
             doc_id      TEXT PRIMARY KEY,
             creator_did TEXT NOT NULL,
             created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
         )",
    ] {
        sqlx::query(statement).execute(pool).await?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::time::Duration;

    use automerge::{transaction::Transactable, Automerge, ReadDoc, ROOT};
    use samod::DocHandle;

    use crate::reach::{add_entry, new_folder, Entry};
    use crate::storage::PostgresStorage;

    pub fn did(name: &str) -> Did {
        Did(format!("did:plc:{name}"))
    }

    /// A relay's worth of state on the test's own database: a repo that
    /// persists to it and the ownership records beside it. Calling it twice on
    /// one pool is a restart.
    pub async fn open(pool: &PgPool) -> (Authz, Repo) {
        let store = PostgresStorage::new(pool.clone());
        store.migrate().await.unwrap();
        let repo = Repo::build_tokio().with_storage(store).load().await;
        let authz = Authz::load(pool.clone(), repo.clone()).await.unwrap();
        (authz, repo)
    }

    /// Wait for something the index does in the background.
    pub async fn eventually(what: &str, check: impl Fn() -> bool) {
        for _ in 0..200 {
            if check() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    impl Authz {
        fn vault_of(&self, doc: &DocumentId) -> Option<DocumentId> {
            self.0.reach.read().unwrap().vault_of(doc).cloned()
        }
    }

    /// A document as a sync client would have sent it: stored, with `creator`
    /// recorded as its first sender.
    async fn sent(authz: &Authz, repo: &Repo, creator: &Did, doc: Automerge) -> DocHandle {
        let handle = repo.create(doc).await.unwrap();
        authz
            .record_creator(handle.document_id(), creator)
            .await
            .unwrap();
        handle
    }

    async fn link(folder: &DocHandle, name: &str, kind: &str, target: &DocumentId) {
        let entry = Entry {
            name: name.to_string(),
            kind: kind.to_string(),
            url: AutomergeUrl::from(target).to_string(),
        };
        folder
            .with_document_async(move |doc| add_entry(doc, &entry))
            .await
            .unwrap()
            .unwrap();
    }

    async fn unlink(folder: &DocHandle, index: usize) {
        folder
            .with_document_async(move |doc| {
                let (_, docs) = doc.get(ROOT, "docs").unwrap().unwrap();
                let mut tx = doc.transaction();
                tx.delete(&docs, index).unwrap();
                tx.commit();
            })
            .await
            .unwrap();
    }

    async fn vault(authz: &Authz, repo: &Repo, owner: &Did, name: &str) -> (DocumentId, DocHandle) {
        let vault = authz.create_vault(owner, name).await.unwrap();
        let root = DocumentId::from_str(&vault.root_doc_id).unwrap();
        let handle = repo.find(root.clone()).await.unwrap().unwrap();
        (root, handle)
    }

    #[sqlx::test(migrations = false)]
    async fn a_vault_root_is_open_to_its_owner_only(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (root, _) = vault(&authz, &repo, &did("alice"), "Notes").await;

        assert!(authz.may_open(&did("alice"), &root));
        assert!(!authz.may_open(&did("bob"), &root));
        assert_eq!(authz.vault_of(&root), Some(root));
    }

    #[sqlx::test(migrations = false)]
    async fn an_unlinked_document_is_open_to_its_creator_only(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let note = sent(&authz, &repo, &did("alice"), Automerge::new()).await;
        let note = note.document_id();

        assert!(authz.may_open(&did("alice"), note));
        assert!(!authz.may_open(&did("bob"), note));
        assert_eq!(authz.vault_of(note), None);
    }

    #[sqlx::test(migrations = false)]
    async fn a_document_nobody_is_recorded_for_is_open_to_nobody(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let stray = repo.create(Automerge::new()).await.unwrap();
        assert!(!authz.may_open(&did("alice"), stray.document_id()));
    }

    #[sqlx::test(migrations = false)]
    async fn the_first_sender_stays_the_creator(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let note = sent(&authz, &repo, &did("alice"), Automerge::new()).await;

        let creator = authz
            .record_creator(note.document_id(), &did("bob"))
            .await
            .unwrap();
        assert_eq!(creator, did("alice"));
        assert!(!authz.may_open(&did("bob"), note.document_id()));
    }

    #[sqlx::test(migrations = false)]
    async fn linked_notes_and_nested_folders_join_the_vault(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (root, root_doc) = vault(&authz, &repo, &alice, "Notes").await;

        let folder = sent(&authz, &repo, &alice, new_folder("Projects").unwrap()).await;
        let note = sent(&authz, &repo, &alice, Automerge::new()).await;
        link(&folder, "plan.md", "md", note.document_id()).await;
        link(&root_doc, "Projects", "folder", folder.document_id()).await;

        let note = note.document_id().clone();
        eventually("the nested note is in the vault", || {
            authz.vault_of(&note) == Some(root.clone())
        })
        .await;
        assert_eq!(authz.vault_of(folder.document_id()), Some(root));
        assert!(authz.may_open(&alice, &note));
        assert!(!authz.may_open(&did("bob"), &note));
    }

    #[sqlx::test(migrations = false)]
    async fn a_link_to_someone_elses_document_is_ignored(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (alice, bob) = (did("alice"), did("bob"));
        let (root, root_doc) = vault(&authz, &repo, &alice, "Notes").await;

        let theirs = sent(&authz, &repo, &bob, Automerge::new()).await;
        let mine = sent(&authz, &repo, &alice, Automerge::new()).await;
        link(&root_doc, "stolen.md", "md", theirs.document_id()).await;
        link(&root_doc, "mine.md", "md", mine.document_id()).await;

        // The second link shows the walk that saw the first has finished.
        let mine = mine.document_id().clone();
        eventually("alice's own note is in the vault", || {
            authz.vault_of(&mine) == Some(root.clone())
        })
        .await;
        assert_eq!(authz.vault_of(theirs.document_id()), None);
        assert!(!authz.may_open(&alice, theirs.document_id()));
        assert!(authz.may_open(&bob, theirs.document_id()));
    }

    #[sqlx::test(migrations = false)]
    async fn a_link_that_arrives_before_the_note_waits_for_its_creator(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (root, root_doc) = vault(&authz, &repo, &alice, "Notes").await;

        // Stored, but nobody is recorded as having sent it yet.
        let note = repo.create(Automerge::new()).await.unwrap();
        let note_id = note.document_id().clone();
        link(&root_doc, "early.md", "md", &note_id).await;

        let marker = sent(&authz, &repo, &alice, Automerge::new()).await;
        link(&root_doc, "marker.md", "md", marker.document_id()).await;
        let marker = marker.document_id().clone();
        eventually("the walk has seen both links", || {
            authz.vault_of(&marker) == Some(root.clone())
        })
        .await;
        assert_eq!(authz.vault_of(&note_id), None);
        assert!(!authz.may_open(&alice, &note_id));

        authz.record_creator(&note_id, &alice).await.unwrap();
        eventually("the waiting link is admitted", || {
            authz.vault_of(&note_id) == Some(root.clone())
        })
        .await;
    }

    #[sqlx::test(migrations = false)]
    async fn a_note_survives_a_move_and_outlives_its_last_entry(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (root, root_doc) = vault(&authz, &repo, &alice, "Notes").await;

        let folder = sent(&authz, &repo, &alice, new_folder("Archive").unwrap()).await;
        let note = sent(&authz, &repo, &alice, Automerge::new()).await;
        let note_id = note.document_id().clone();
        link(&root_doc, "Archive", "folder", folder.document_id()).await;
        link(&root_doc, "a.md", "md", &note_id).await;
        eventually("the note is in the vault", || {
            authz.vault_of(&note_id) == Some(root.clone())
        })
        .await;

        // A move adds the new entry before removing the old one.
        link(&folder, "a.md", "md", &note_id).await;
        unlink(&root_doc, 1).await;
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(authz.vault_of(&note_id), Some(root));

        // Deleted: out of the vault, still its creator's.
        unlink(&folder, 0).await;
        eventually("the note has left the vault", || {
            authz.vault_of(&note_id).is_none()
        })
        .await;
        assert!(authz.may_open(&alice, &note_id));
        assert!(!authz.may_open(&did("bob"), &note_id));
    }

    #[sqlx::test(migrations = false)]
    async fn entries_of_other_types_are_left_alone(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (root, root_doc) = vault(&authz, &repo, &alice, "Notes").await;

        let canvas = sent(&authz, &repo, &alice, Automerge::new()).await;
        let note = sent(&authz, &repo, &alice, Automerge::new()).await;
        link(&root_doc, "board.canvas", "canvas", canvas.document_id()).await;
        link(&root_doc, "a.md", "md", note.document_id()).await;

        let note = note.document_id().clone();
        eventually("the note is in the vault", || {
            authz.vault_of(&note) == Some(root.clone())
        })
        .await;
        assert_eq!(authz.vault_of(canvas.document_id()), None);
    }

    #[sqlx::test(migrations = false)]
    async fn a_change_in_the_vault_sets_its_last_change(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (_, root_doc) = vault(&authz, &repo, &alice, "Notes").await;
        assert!(authz.list_vaults(&alice).await.unwrap()[0]
            .last_change_at
            .is_none());

        let note = sent(&authz, &repo, &alice, Automerge::new()).await;
        link(&root_doc, "a.md", "md", note.document_id()).await;

        for _ in 0..100 {
            if authz.list_vaults(&alice).await.unwrap()[0]
                .last_change_at
                .is_some()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("last change was never set");
    }

    #[sqlx::test(migrations = false)]
    async fn vault_names_are_unique_per_owner_whatever_the_case(pool: PgPool) {
        let (authz, _repo) = open(&pool).await;
        let alice = did("alice");
        authz.create_vault(&alice, "  Notes ").await.unwrap();

        let again = authz.create_vault(&alice, "notes").await;
        assert!(matches!(again, Err(CreateVaultError::NameTaken)));
        authz.create_vault(&did("bob"), "Notes").await.unwrap();
        authz.create_vault(&alice, "Work").await.unwrap();

        let names: Vec<_> = authz
            .list_vaults(&alice)
            .await
            .unwrap()
            .into_iter()
            .map(|vault| vault.name)
            .collect();
        assert_eq!(names, ["Notes", "Work"]);

        for bad in ["", "   ", &"x".repeat(101)] {
            let result = authz.create_vault(&alice, bad).await;
            assert!(matches!(result, Err(CreateVaultError::InvalidName)));
        }
        authz.create_vault(&alice, &"x".repeat(100)).await.unwrap();
    }

    #[sqlx::test(migrations = false)]
    async fn a_restart_loses_nothing(pool: PgPool) {
        let alice = did("alice");
        let (root, note_id) = {
            let (authz, repo) = open(&pool).await;
            let (root, root_doc) = vault(&authz, &repo, &alice, "Notes").await;
            let note = sent(&authz, &repo, &alice, Automerge::new()).await;
            let note_id = note.document_id().clone();
            link(&root_doc, "a.md", "md", &note_id).await;
            eventually("the note is in the vault", || {
                authz.vault_of(&note_id) == Some(root.clone())
            })
            .await;
            repo.stop().await;
            (root, note_id)
        };

        let (authz, _repo) = open(&pool).await;
        let vaults = authz.list_vaults(&alice).await.unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].root_doc_id, root.to_string());
        assert!(authz.may_open(&alice, &root));
        assert!(!authz.may_open(&did("bob"), &note_id));
        eventually("the index is rebuilt from storage", || {
            authz.vault_of(&note_id) == Some(root.clone())
        })
        .await;
    }
}
