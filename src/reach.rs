//! Which documents each vault reaches.
//!
//! A vault's root is a folder document, a folder lists entries, and an entry
//! points at a note or another folder. Walking from the root gives the set of
//! documents in the vault. That set is what paths, tools and search work from.
//!
//! It is derived and rebuildable: never authoritative, never persisted. The
//! authority is the folder documents themselves plus `doc_creators`.
//!
//! **Admission rule.** A document joins a vault's set only if the vault's owner
//! created it. Without that, a member could reach someone else's document by
//! writing its URL into their own folder.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use automerge::{transaction::Transactable, Automerge, AutomergeError, ObjType, ReadDoc, ROOT};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use samod::{AutomergeUrl, DocHandle, DocumentId};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::auth::Did;
use crate::authz::Authz;

/// The shortest gap between two rebuilds of one vault. A first import changes
/// folder documents thousands of times.
const REBUILD_INTERVAL: Duration = Duration::from_secs(1);

/// How long to wait for a document the index expects the relay to hold.
const LOAD_TIMEOUT: Duration = Duration::from_secs(10);

/// How many rebuilds in a row may go looking for a folder that will not load.
const MAX_LOAD_RETRIES: u8 = 5;

/// How often changed vaults have `last_change_at` written. Never per edit.
const LAST_CHANGE_FLUSH: Duration = Duration::from_secs(60);

/// The entry type that marks a folder. Every other type is a file extension.
pub(crate) const FOLDER: &str = "folder";
/// The only file type the relay acts on.
pub(crate) const NOTE: &str = "md";

#[derive(Default)]
pub(crate) struct Index {
    vaults: HashMap<DocumentId, VaultReach>,
    /// Every reachable document, and the root of the vault that reaches it.
    doc_to_root: HashMap<DocumentId, DocumentId>,
}

struct VaultReach {
    owner: Did,
    docs: HashSet<DocumentId>,
    /// Linked from a folder, creator not yet known. A folder change can arrive
    /// before the linked note's first frame.
    pending: HashSet<DocumentId>,
    /// Asks the vault's task for a rebuild. Holds at most one request, which is
    /// what collapses a burst of folder changes into one walk.
    wake: Arc<Notify>,
    /// One task per reachable document, listening for changes.
    watchers: HashMap<DocumentId, JoinHandle<()>>,
    load_retries: u8,
    last_change: Option<DateTime<Utc>>,
    /// `last_change` is newer than the table.
    unsaved: bool,
}

impl Index {
    pub(crate) fn owner_of(&self, doc: &DocumentId) -> Option<&Did> {
        let root = self.doc_to_root.get(doc)?;
        self.vaults.get(root).map(|vault| &vault.owner)
    }

    /// The root of the vault a document is in, if any.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn vault_of(&self, doc: &DocumentId) -> Option<&DocumentId> {
        self.doc_to_root.get(doc)
    }

    pub(crate) fn last_change(&self, root: &DocumentId) -> Option<DateTime<Utc>> {
        self.vaults.get(root)?.last_change
    }

    /// A creator has just been recorded: rebuild any vault that was waiting to
    /// learn it.
    pub(crate) fn wake_pending(&self, doc: &DocumentId) {
        for vault in self.vaults.values() {
            if vault.pending.contains(doc) {
                vault.wake.notify_one();
            }
        }
    }
}

/// One line of a folder document's `docs` list.
#[derive(Debug, PartialEq)]
pub(crate) struct Entry {
    pub name: String,
    pub kind: String,
    pub url: String,
}

impl Entry {
    pub(crate) fn doc_id(&self) -> Option<DocumentId> {
        Some(AutomergeUrl::from_str(&self.url).ok()?.document_id().clone())
    }
}

/// Read a string that may be stored either way.
///
/// The JS client writes a string as a text object. Older writers and other
/// tools store a scalar. Both mean the same thing here.
pub(crate) fn read_string(doc: &Automerge, obj: &automerge::ObjId, key: &str) -> Option<String> {
    match doc.get(obj, key).ok()?? {
        (automerge::Value::Object(ObjType::Text), id) => doc.text(id).ok(),
        (automerge::Value::Scalar(scalar), _) => Some(scalar.as_str()?.to_string()),
        _ => None,
    }
}

pub(crate) fn put_string(
    tx: &mut impl Transactable,
    obj: &automerge::ObjId,
    key: &str,
    value: &str,
) -> Result<(), AutomergeError> {
    let text = tx.put_object(obj, key, ObjType::Text)?;
    tx.splice_text(&text, 0, 0, value)
}

/// The entries of a folder document. An entry missing a field is skipped, and
/// a document that is not a folder has none.
pub(crate) fn read_entries(doc: &Automerge) -> Vec<Entry> {
    let Ok(Some((automerge::Value::Object(ObjType::List), docs))) = doc.get(ROOT, "docs") else {
        return Vec::new();
    };
    (0..doc.length(&docs))
        .filter_map(|i| {
            let (automerge::Value::Object(ObjType::Map), entry) = doc.get(&docs, i).ok()?? else {
                return None;
            };
            Some(Entry {
                name: read_string(doc, &entry, "name")?,
                kind: read_string(doc, &entry, "type")?,
                url: read_string(doc, &entry, "url")?,
            })
        })
        .collect()
}

/// An empty folder document: `{"@patchwork": {"type": "folder"}, title, docs}`.
///
/// Strings are written as text objects, the way the JS client writes them, so
/// a client reads the same shape whichever side made the folder.
pub(crate) fn new_folder(title: &str) -> Result<Automerge, AutomergeError> {
    let mut doc = Automerge::new();
    let mut tx = doc.transaction();
    let patchwork = tx.put_object(ROOT, "@patchwork", ObjType::Map)?;
    put_string(&mut tx, &patchwork, "type", FOLDER)?;
    put_string(&mut tx, &ROOT, "title", title)?;
    tx.put_object(ROOT, "docs", ObjType::List)?;
    tx.commit();
    Ok(doc)
}

/// Append an entry to a folder document's `docs` list.
pub(crate) fn add_entry(doc: &mut Automerge, entry: &Entry) -> Result<(), AutomergeError> {
    let Some((automerge::Value::Object(ObjType::List), docs)) = doc.get(ROOT, "docs")? else {
        return Err(AutomergeError::InvalidOp(ObjType::Map));
    };
    let mut tx = doc.transaction();
    let item = tx.insert_object(&docs, tx.length(&docs), ObjType::Map)?;
    put_string(&mut tx, &item, "name", &entry.name)?;
    put_string(&mut tx, &item, "type", &entry.kind)?;
    put_string(&mut tx, &item, "url", &entry.url)?;
    tx.commit();
    Ok(())
}

impl Authz {
    /// Begin indexing a vault: now, and again whenever one of its folders
    /// changes, at most once per [`REBUILD_INTERVAL`].
    pub(crate) fn start_vault(
        &self,
        root: DocumentId,
        owner: Did,
        last_change: Option<DateTime<Utc>>,
    ) {
        let wake = Arc::new(Notify::new());
        {
            let mut index = self.0.reach.write().unwrap();
            // The root is in its own vault from the start, before any walk.
            index.doc_to_root.insert(root.clone(), root.clone());
            index.vaults.insert(
                root.clone(),
                VaultReach {
                    owner,
                    docs: HashSet::from([root.clone()]),
                    pending: HashSet::new(),
                    wake: Arc::clone(&wake),
                    watchers: HashMap::new(),
                    load_retries: 0,
                    last_change,
                    unsaved: false,
                },
            );
        }

        wake.notify_one();
        let authz = self.clone();
        tokio::spawn(async move {
            loop {
                wake.notified().await;
                authz.rebuild(&root).await;
                tokio::time::sleep(REBUILD_INTERVAL).await;
            }
        });
    }

    pub(crate) async fn open(&self, doc: &DocumentId) -> Option<DocHandle> {
        match tokio::time::timeout(LOAD_TIMEOUT, self.0.repo.find(doc.clone())).await {
            Ok(Ok(handle)) => handle,
            _ => None,
        }
    }

    /// Walk the vault's folders from its root and replace its reachable set.
    async fn rebuild(&self, root: &DocumentId) {
        let Some((owner, wake)) = self
            .0
            .reach
            .read()
            .unwrap()
            .vaults
            .get(root)
            .map(|vault| (vault.owner.clone(), Arc::clone(&vault.wake)))
        else {
            return;
        };

        let mut docs = HashSet::from([root.clone()]);
        let mut pending = HashSet::new();
        let mut folders = vec![root.clone()];
        let mut notes = Vec::new();
        let mut loaded = HashMap::new();
        let mut missing_folder = false;

        while let Some(folder) = folders.pop() {
            let Some(handle) = self.open(&folder).await else {
                missing_folder = true;
                continue;
            };
            // Listen before reading, so a change that lands during the read
            // still asks for another walk.
            let changes = handle.changes();
            let entries = handle
                .with_document_async(|doc| read_entries(doc))
                .await
                .unwrap_or_default();
            loaded.insert(folder, (handle, changes));

            for entry in entries {
                // Anything that is not a folder or a note is left alone: not
                // walked, not listed, not admitted.
                if entry.kind != FOLDER && entry.kind != NOTE {
                    continue;
                }
                let Some(id) = entry.doc_id() else { continue };
                if docs.contains(&id) || pending.contains(&id) {
                    continue;
                }
                match self.creator_of(&id) {
                    Some(creator) if creator == owner => {
                        docs.insert(id.clone());
                        if entry.kind == FOLDER {
                            folders.push(id);
                        } else {
                            notes.push(id);
                        }
                    }
                    Some(creator) => tracing::warn!(
                        vault = %root, doc = %id, %owner, %creator,
                        "ignoring a link to a document its vault's owner did not create"
                    ),
                    None => {
                        pending.insert(id);
                    }
                }
            }
        }

        let mut guard = self.0.reach.write().unwrap();
        let index = &mut *guard;
        let Some(vault) = index.vaults.get_mut(root) else {
            return;
        };

        for gone in vault.docs.difference(&docs) {
            if index.doc_to_root.get(gone) == Some(root) {
                index.doc_to_root.remove(gone);
            }
        }
        for doc in &docs {
            index.doc_to_root.insert(doc.clone(), root.clone());
        }
        vault.watchers.retain(|doc, watcher| {
            let keep = docs.contains(doc) && !watcher.is_finished();
            if !keep {
                watcher.abort();
            }
            keep
        });
        for (folder, (handle, changes)) in loaded {
            vault.watchers.entry(folder).or_insert_with(|| {
                tokio::spawn(self.clone().watch(root.clone(), handle, changes, true))
            });
        }
        for note in notes {
            vault
                .watchers
                .entry(note.clone())
                .or_insert_with(|| tokio::spawn(self.clone().watch_note(root.clone(), note)));
        }

        // A creator recorded while this walk was running found nothing waiting
        // for it. Walk again rather than leave the link pending for good.
        let creators = self.0.creators.read().unwrap();
        let learned = pending.iter().any(|doc| creators.contains_key(doc));
        drop(creators);

        vault.docs = docs;
        vault.pending = pending;

        // A folder with a creator row and no content yet: its first frame has
        // been seen and the rest is still arriving. Look again shortly, a
        // bounded number of times, because nothing else will prompt it.
        if missing_folder && vault.load_retries < MAX_LOAD_RETRIES {
            vault.load_retries += 1;
            wake.notify_one();
        } else if !missing_folder {
            vault.load_retries = 0;
        }
        if learned {
            wake.notify_one();
        }
    }

    /// Note every change to one document, and for a folder ask for a rebuild.
    async fn watch(
        self,
        root: DocumentId,
        // Held so the document stays loaded for as long as it is watched.
        _handle: DocHandle,
        changes: impl futures::Stream,
        is_folder: bool,
    ) {
        futures::pin_mut!(changes);
        while changes.next().await.is_some() {
            let mut index = self.0.reach.write().unwrap();
            let Some(vault) = index.vaults.get_mut(&root) else {
                return;
            };
            vault.last_change = Some(Utc::now());
            vault.unsaved = true;
            if is_folder {
                vault.wake.notify_one();
            }
        }
    }

    async fn watch_note(self, root: DocumentId, note: DocumentId) {
        // A note that will not load is tried again on the vault's next rebuild.
        if let Some(handle) = self.open(&note).await {
            let changes = handle.changes();
            self.watch(root, handle, changes, false).await;
        }
    }

    /// Write `last_change_at` for the vaults that changed, once a minute.
    pub(crate) fn start_last_change_flush(&self) {
        let authz = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(LAST_CHANGE_FLUSH).await;
                let changed: Vec<_> = authz
                    .0
                    .reach
                    .write()
                    .unwrap()
                    .vaults
                    .iter_mut()
                    .filter(|(_, vault)| vault.unsaved)
                    .map(|(root, vault)| {
                        vault.unsaved = false;
                        (root.to_string(), vault.last_change)
                    })
                    .collect();
                for (root, at) in changed {
                    let saved =
                        sqlx::query("UPDATE vaults SET last_change_at = $1 WHERE root_doc_id = $2")
                            .bind(at)
                            .bind(&root)
                            .execute(&authz.0.pool)
                            .await;
                    if let Err(e) = saved {
                        tracing::warn!(vault = %root, error = %e, "could not save last change");
                    }
                }
            }
        });
    }
}
