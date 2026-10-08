//! What the tools do to a vault's documents.
//!
//! A tool addresses a note by vault and path. The path is resolved by walking
//! folder documents from the vault's root at the time of the call, so a note
//! with no folder entry cannot be reached by any tool, and a note that has
//! moved is found where it now is.
//!
//! Every document touched is checked twice over: through [`Authz::may_open`],
//! and against the admission rule, that the caller created it. The second is
//! what stops a link someone wrote into a folder from leading to a document
//! that is not the owner's.
//!
//! Writes are splices into a note's text. Nothing here replaces a note whole:
//! a replace would discard whatever another device typed in the meantime.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use automerge::{
    transaction::Transactable, Automerge, AutomergeError, ObjId, ObjType, ReadDoc, TextEncoding,
    Value, ROOT,
};
use samod::{AutomergeUrl, DocHandle, DocumentId};
use unicode_normalization::UnicodeNormalization;

use crate::auth::Did;
use crate::authz::Authz;
use crate::reach::{self, Entry, FOLDER, NOTE};

/// Why a tool could not do what it was asked.
#[derive(Debug)]
pub enum NoteError {
    /// The caller's to fix. The text is shown to them.
    Refused(String),
    /// Ours. Logged, and not described to the caller.
    Internal(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for NoteError {
    fn from(e: E) -> Self {
        NoteError::Internal(e.into())
    }
}

fn refuse<T>(why: impl Into<String>) -> Result<T> {
    Err(NoteError::Refused(why.into()))
}

type Result<T> = std::result::Result<T, NoteError>;

/// The most entries a recursive listing or a search will walk.
const MAX_WALK: usize = 20_000;

/// A note or folder as a path leads to it.
#[derive(Clone, Debug)]
pub struct Item {
    pub name: String,
    pub is_folder: bool,
    pub id: DocumentId,
}

/// A note or folder with the path it was found at.
#[derive(Clone, Debug)]
pub struct Found {
    pub path: String,
    pub is_folder: bool,
    pub id: DocumentId,
}

/// One caller's view of the vaults: everything here acts as `did`.
pub struct Notes<'a> {
    pub authz: &'a Authz,
    pub did: &'a Did,
}

/// How two names are compared: equal after NFC and case folding. macOS and
/// iOS file systems cannot hold two names that differ only that way.
fn key(name: &str) -> String {
    name.nfc().collect::<String>().to_lowercase()
}

/// Split a path into its segments. A leading or trailing slash is tolerated;
/// `.` and `..` are not.
fn segments(path: &str) -> Result<Vec<&str>> {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if parts.iter().any(|part| *part == "." || *part == "..") {
        return refuse("a path cannot contain . or ..");
    }
    Ok(parts)
}

/// Check a name that is about to be written, and return it in NFC.
fn new_name(name: &str) -> Result<String> {
    if name.starts_with('.') {
        return refuse(format!("{name:?} starts with a dot, which is not synced"));
    }
    Ok(name.nfc().collect())
}

/// The length of a string in the units this document counts text positions in.
fn width(encoding: TextEncoding, s: &str) -> usize {
    match encoding {
        TextEncoding::Utf8CodeUnit => s.len(),
        TextEncoding::Utf16CodeUnit => s.encode_utf16().count(),
        _ => s.chars().count(),
    }
}

/// Trim what `old` and `new` share at both ends, leaving the smallest change.
/// Returns the shared prefix and the differing middle of each.
fn narrow<'a>(old: &'a str, new: &'a str) -> (&'a str, &'a str, &'a str) {
    let prefix: usize = old
        .chars()
        .zip(new.chars())
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a.len_utf8())
        .sum();
    let (old_rest, new_rest) = (&old[prefix..], &new[prefix..]);
    let suffix: usize = old_rest
        .chars()
        .rev()
        .zip(new_rest.chars().rev())
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a.len_utf8())
        .sum();
    (
        &old[..prefix],
        &old_rest[..old_rest.len() - suffix],
        &new_rest[..new_rest.len() - suffix],
    )
}

/// A note document: `{"@patchwork": {"type": "file"}, name, extension,
/// mimeType, content}`, with `content` a text object holding the text exactly.
fn new_note(name: &str, content: &str) -> std::result::Result<Automerge, AutomergeError> {
    let mut doc = Automerge::new();
    let mut tx = doc.transaction();
    let patchwork = tx.put_object(ROOT, "@patchwork", ObjType::Map)?;
    reach::put_string(&mut tx, &patchwork, "type", "file")?;
    reach::put_string(&mut tx, &ROOT, "name", name)?;
    reach::put_string(&mut tx, &ROOT, "extension", NOTE)?;
    reach::put_string(&mut tx, &ROOT, "mimeType", "text/markdown")?;
    reach::put_string(&mut tx, &ROOT, "content", content)?;
    tx.commit();
    Ok(doc)
}

/// A note's text object, or a refusal if the note is not shaped like one.
fn content_of(doc: &Automerge) -> Result<ObjId> {
    match doc.get(ROOT, "content")? {
        Some((Value::Object(ObjType::Text), content)) => Ok(content),
        _ => refuse("this note's content is not editable text"),
    }
}

impl Notes<'_> {
    /// May the caller reach this document through a folder of their vault?
    fn admitted(&self, doc: &DocumentId) -> bool {
        self.authz.may_open(self.did, doc) && self.authz.creator_of(doc).as_ref() == Some(self.did)
    }

    async fn open(&self, doc: &DocumentId) -> Result<DocHandle> {
        match self.authz.open(doc).await {
            Some(handle) => Ok(handle),
            None => Err(NoteError::Internal(anyhow::anyhow!(
                "document {doc} is linked from a vault and would not load"
            ))),
        }
    }

    /// Find one of the caller's vaults by name, or their only vault if no name
    /// is given. Returns its root document and its name.
    pub async fn vault(&self, name: Option<&str>) -> Result<(DocumentId, String)> {
        let vaults = self.authz.list_vaults(self.did).await?;
        let chosen = match name.map(str::trim).filter(|name| !name.is_empty()) {
            Some(name) => vaults
                .iter()
                .find(|vault| vault.name.to_lowercase() == name.to_lowercase()),
            None if vaults.len() == 1 => vaults.first(),
            None if vaults.is_empty() => None,
            None => {
                let names: Vec<_> = vaults.iter().map(|vault| vault.name.as_str()).collect();
                return refuse(format!(
                    "you have more than one vault; name one of: {}",
                    names.join(", ")
                ));
            }
        };
        match chosen {
            Some(vault) => Ok((
                DocumentId::from_str(&vault.root_doc_id).map_err(|e| anyhow::anyhow!("{e:?}"))?,
                vault.name.clone(),
            )),
            None => refuse("no vault by that name; list_vaults shows the ones you have"),
        }
    }

    /// Every entry of a folder as written, whatever its type or owner.
    async fn raw_entries(&self, folder: &DocumentId) -> Result<Vec<Entry>> {
        let handle = self.open(folder).await?;
        Ok(handle
            .with_document_async(|doc| reach::read_entries(doc))
            .await
            .map_err(|_| anyhow::anyhow!("repo stopped"))?)
    }

    /// The notes and folders in a folder, by name.
    ///
    /// Where two entries' names collide, the one whose URL sorts lowest is the
    /// one the name refers to. Clients rename the others.
    async fn items(&self, folder: &DocumentId) -> Result<Vec<Item>> {
        let mut by_key: HashMap<String, (String, Item)> = HashMap::new();
        for entry in self.raw_entries(folder).await? {
            if entry.kind != FOLDER && entry.kind != NOTE {
                continue;
            }
            let Some(id) = entry.doc_id() else { continue };
            if !self.admitted(&id) {
                continue;
            }
            let item = Item {
                is_folder: entry.kind == FOLDER,
                name: entry.name,
                id,
            };
            match by_key.entry(key(&item.name)) {
                std::collections::hash_map::Entry::Occupied(mut held) => {
                    if entry.url < held.get().0 {
                        held.insert((entry.url, item));
                    }
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert((entry.url, item));
                }
            }
        }
        let mut items: Vec<Item> = by_key.into_values().map(|(_, item)| item).collect();
        items.sort_by_key(|item| key(&item.name));
        Ok(items)
    }

    async fn child(&self, folder: &DocumentId, name: &str) -> Result<Option<Item>> {
        let wanted = key(name);
        Ok(self
            .items(folder)
            .await?
            .into_iter()
            .find(|item| key(&item.name) == wanted))
    }

    /// Follow a path from a vault's root. An empty path is the root itself.
    ///
    /// Returns what the path leads to, and the path as the folders spell it,
    /// which may differ from the one asked for in letter case.
    async fn resolve(&self, root: &DocumentId, path: &str) -> Result<Option<(Item, String)>> {
        let mut at = Item {
            name: String::new(),
            is_folder: true,
            id: root.clone(),
        };
        let mut names = Vec::new();
        for segment in segments(path)? {
            if !at.is_folder {
                return Ok(None);
            }
            match self.child(&at.id, segment).await? {
                Some(item) => at = item,
                None => return Ok(None),
            }
            names.push(at.name.clone());
        }
        Ok(Some((at, names.join("/"))))
    }

    async fn note(&self, root: &DocumentId, path: &str) -> Result<DocHandle> {
        match self.resolve(root, path).await? {
            Some((item, _)) if !item.is_folder => self.open(&item.id).await,
            Some(_) => refuse(format!("{path} is a folder, not a note")),
            None => refuse(format!("no note at {path}")),
        }
    }

    /// The notes and folders under a path, one level or all the way down.
    pub async fn list(&self, root: &DocumentId, path: &str, recursive: bool) -> Result<Vec<Found>> {
        let (start, prefix) = match self.resolve(root, path).await? {
            Some((item, spelled)) if item.is_folder => (item, spelled),
            Some(_) => return refuse(format!("{path} is a note, not a folder")),
            None => return refuse(format!("no folder at {path}")),
        };

        let mut found = Vec::new();
        let mut seen = HashSet::from([start.id.clone()]);
        let mut queue = vec![(prefix, start.id)];
        while let Some((prefix, folder)) = queue.pop() {
            for item in self.items(&folder).await? {
                let path = if prefix.is_empty() {
                    item.name.clone()
                } else {
                    format!("{prefix}/{}", item.name)
                };
                // A folder linked from two places is walked once.
                if item.is_folder && recursive && seen.insert(item.id.clone()) {
                    queue.push((path.clone(), item.id.clone()));
                }
                found.push(Found {
                    path,
                    is_folder: item.is_folder,
                    id: item.id,
                });
                if found.len() >= MAX_WALK {
                    return refuse(format!(
                        "more than {MAX_WALK} entries; list a folder further down"
                    ));
                }
            }
        }
        found.sort_by_key(|found| key(&found.path));
        Ok(found)
    }

    pub async fn read(&self, root: &DocumentId, path: &str) -> Result<String> {
        self.read_doc(&self.note(root, path).await?).await
    }

    pub async fn read_doc(&self, handle: &DocHandle) -> Result<String> {
        let text = handle
            .with_document_async(|doc| reach::read_string(doc, &ROOT, "content"))
            .await
            .map_err(|_| anyhow::anyhow!("repo stopped"))?;
        match text {
            Some(text) => Ok(text),
            None => refuse("this note has no text content"),
        }
    }

    /// Store a new document as the caller's and return its URL.
    async fn store(&self, doc: Automerge) -> Result<String> {
        let handle = self
            .authz
            .0
            .repo
            .create(doc)
            .await
            .map_err(|_| anyhow::anyhow!("repo stopped"))?;
        self.authz
            .record_creator(handle.document_id(), self.did)
            .await?;
        Ok(AutomergeUrl::from(handle.document_id()).to_string())
    }

    async fn link(&self, folder: &DocumentId, name: String, kind: &str, url: String) -> Result<()> {
        let entry = Entry {
            name,
            kind: kind.to_string(),
            url,
        };
        self.open(folder)
            .await?
            .with_document_async(move |doc| reach::add_entry(doc, &entry))
            .await
            .map_err(|_| anyhow::anyhow!("repo stopped"))??;
        Ok(())
    }

    /// Does any entry in the folder, of any type, collide with this name?
    async fn taken(&self, folder: &DocumentId, name: &str) -> Result<bool> {
        let wanted = key(name);
        Ok(self
            .raw_entries(folder)
            .await?
            .iter()
            .any(|entry| key(&entry.name) == wanted))
    }

    /// Create a note at a path, making any folders on the way that are missing.
    /// Refuses a path that already has an entry.
    pub async fn create(&self, root: &DocumentId, path: &str, content: &str) -> Result<String> {
        let mut parts = segments(path)?;
        let Some(file) = parts.pop() else {
            return refuse("give the note a path, such as Projects/plan.md");
        };
        if !file.ends_with(".md") || file == ".md" {
            return refuse("a note's name ends in .md");
        }
        let file = new_name(file)?;

        let mut folder = root.clone();
        let mut at = String::new();
        for part in parts {
            at = if at.is_empty() {
                part.to_string()
            } else {
                format!("{at}/{part}")
            };
            folder = match self.child(&folder, part).await? {
                Some(item) if item.is_folder => item.id,
                Some(_) => return refuse(format!("{at} is a note, not a folder")),
                None if self.taken(&folder, part).await? => {
                    return refuse(format!("{at} exists and is not a folder this tool can use"));
                }
                None => {
                    let name = new_name(part)?;
                    let url = self.store(reach::new_folder(&name)?).await?;
                    self.link(&folder, name, FOLDER, url.clone()).await?;
                    AutomergeUrl::from_str(&url)
                        .map_err(|e| anyhow::anyhow!("{e:?}"))?
                        .document_id()
                        .clone()
                }
            };
        }

        if self.taken(&folder, &file).await? {
            return refuse(format!("{path} already exists; use edit_note or append_note"));
        }
        // The note first, then its entry: an entry is never left pointing at
        // a document that does not exist.
        let url = self.store(new_note(&file, content)?).await?;
        self.link(&folder, file.clone(), NOTE, url).await?;

        Ok(if at.is_empty() {
            file
        } else {
            format!("{at}/{file}")
        })
    }

    /// Replace `old` with `new` in a note, and return how many places changed.
    ///
    /// With one match, or `replace_all`, each is spliced where it stands.
    /// Several matches without `replace_all` is refused: guessing which one
    /// was meant is how a model edits the wrong paragraph.
    pub async fn edit(
        &self,
        root: &DocumentId,
        path: &str,
        old: String,
        new: String,
        replace_all: bool,
    ) -> Result<usize> {
        if old.is_empty() {
            return refuse("old_text is empty; use append_note to add text");
        }
        if old == new {
            return refuse("old_text and new_text are the same");
        }
        self.note(root, path)
            .await?
            .with_document_async(move |doc| {
                let content = content_of(doc)?;
                let text = doc.text(&content)?;
                let matches: Vec<usize> = text.match_indices(&old).map(|(at, _)| at).collect();
                match matches.len() {
                    0 => return refuse("old_text was not found in the note"),
                    1 => {}
                    n if !replace_all => {
                        return refuse(format!(
                            "old_text matches {n} places; include more of the surrounding \
                             text, or set replace_all"
                        ));
                    }
                    _ => {}
                }

                let encoding = doc.text_encoding();
                let (prefix, old_middle, new_middle) = narrow(&old, &new);
                let mut tx = doc.transaction();
                // Last match first, so the positions of the earlier ones hold.
                for at in matches.iter().rev() {
                    let position = width(encoding, &text[..*at]) + width(encoding, prefix);
                    let delete = width(encoding, old_middle) as isize;
                    tx.splice_text(&content, position, delete, new_middle)?;
                }
                tx.commit();
                Ok(matches.len())
            })
            .await
            .map_err(|_| anyhow::anyhow!("repo stopped"))?
    }

    /// Add text to the end of a note, starting on a new line.
    pub async fn append(&self, root: &DocumentId, path: &str, text: String) -> Result<()> {
        if text.is_empty() {
            return refuse("text is empty");
        }
        self.note(root, path)
            .await?
            .with_document_async(move |doc| {
                let content = content_of(doc)?;
                let existing = doc.text(&content)?;
                let separator = if existing.is_empty() || existing.ends_with('\n') {
                    ""
                } else {
                    "\n"
                };
                let end = doc.length(&content);
                let mut tx = doc.transaction();
                tx.splice_text(&content, end, 0, &format!("{separator}{text}"))?;
                tx.commit();
                Ok(())
            })
            .await
            .map_err(|_| anyhow::anyhow!("repo stopped"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrow_leaves_only_what_differs() {
        assert_eq!(narrow("the quick fox", "the slow fox"), ("the ", "quick", "slow"));
        assert_eq!(narrow("abc", "abcd"), ("abc", "", "d"));
        assert_eq!(narrow("abcd", "abc"), ("abc", "d", ""));
        assert_eq!(narrow("aXa", "aa"), ("a", "X", ""));
        assert_eq!(narrow("old", "new"), ("", "old", "new"));
        // Shared characters are whole characters, never half of one.
        assert_eq!(narrow("é1", "é2"), ("é", "1", "2"));
        assert_eq!(narrow("1é", "2é"), ("", "1", "2"));
    }

    #[test]
    fn width_counts_in_the_documents_units() {
        assert_eq!(width(TextEncoding::UnicodeCodePoint, "a😀é"), 3);
        assert_eq!(width(TextEncoding::Utf16CodeUnit, "a😀é"), 4);
        assert_eq!(width(TextEncoding::Utf8CodeUnit, "a😀é"), 7);
    }

    #[test]
    fn names_compare_after_nfc_and_case_folding() {
        // "é" precomposed and as "e" plus a combining accent.
        assert_eq!(key("Caf\u{e9}.md"), key("cafe\u{301}.MD"));
        assert_ne!(key("a.md"), key("b.md"));
    }

    #[test]
    fn paths_split_into_segments() {
        assert_eq!(segments("/Projects//plan.md/").unwrap(), ["Projects", "plan.md"]);
        assert!(segments("").unwrap().is_empty());
        assert!(matches!(segments("a/../b"), Err(NoteError::Refused(_))));
    }
}
