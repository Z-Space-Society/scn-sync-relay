//! Text search across one vault.
//!
//! Each search walks the vault's folders and reads its notes from the
//! documents the relay already holds in memory. Nothing is kept between
//! searches, so there is no index to fall out of step: a note that was deleted
//! is not found, and a note that moved is found at its new path.

use samod::DocumentId;

use super::notes::{NoteError, Notes};

/// The longest a line quoted in a result may be, in characters.
const SNIPPET_CHARS: usize = 200;
/// The most lines quoted for one note.
const SNIPPETS_PER_NOTE: usize = 3;

pub struct Hit {
    pub path: String,
    /// How many times the query's words appear in the note.
    pub count: usize,
    /// The first few lines that contain one of the words.
    pub lines: Vec<String>,
}

/// The lowercase words of a query. A note matches when it contains them all.
fn terms(query: &str) -> Vec<String> {
    query.split_whitespace().map(str::to_lowercase).collect()
}

/// Score one note against the query's words, or `None` if a word is missing
/// from both its text and its path.
fn score(path: &str, text: &str, terms: &[String]) -> Option<Hit> {
    let lower_text = text.to_lowercase();
    let lower_path = path.to_lowercase();
    let mut count = 0;
    for term in terms {
        let in_text = lower_text.matches(term.as_str()).count();
        if in_text == 0 && !lower_path.contains(term.as_str()) {
            return None;
        }
        count += in_text;
    }

    let lines = text
        .lines()
        .filter(|line| {
            let line = line.to_lowercase();
            terms.iter().any(|term| line.contains(term.as_str()))
        })
        .take(SNIPPETS_PER_NOTE)
        .map(|line| {
            let line = line.trim();
            if line.chars().count() > SNIPPET_CHARS {
                format!("{}…", line.chars().take(SNIPPET_CHARS).collect::<String>())
            } else {
                line.to_string()
            }
        })
        .collect();

    Some(Hit {
        path: path.to_string(),
        count,
        lines,
    })
}

/// The notes in a vault that contain every word of the query, best first.
pub async fn search(
    notes: &Notes<'_>,
    root: &DocumentId,
    query: &str,
    limit: usize,
) -> Result<Vec<Hit>, NoteError> {
    let terms = terms(query);
    if terms.is_empty() {
        return Err(NoteError::Refused("query is empty".to_string()));
    }

    let mut hits = Vec::new();
    for found in notes.list(root, "", true).await? {
        if found.is_folder {
            continue;
        }
        // A note that will not load or has no text is skipped, not fatal:
        // one bad document should not hide the rest of the vault.
        let Some(handle) = notes.authz.open(&found.id).await else {
            continue;
        };
        let Ok(text) = notes.read_doc(&handle).await else {
            continue;
        };
        hits.extend(score(&found.path, &text, &terms));
    }

    hits.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.path.cmp(&b.path)));
    hits.truncate(limit);
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_note_matches_when_every_word_is_in_its_text_or_path() {
        let text = "# Plan\nShip the relay first.\nThen Corliss.\n";
        let words = |query: &str| terms(query);

        let hit = score("Projects/plan.md", text, &words("RELAY ship")).unwrap();
        assert_eq!(hit.count, 2);
        assert_eq!(hit.lines, ["Ship the relay first."]);

        // "projects" is only in the path, which still counts as a match.
        assert!(score("Projects/plan.md", text, &words("projects corliss")).is_some());
        assert!(score("Projects/plan.md", text, &words("relay plugin")).is_none());
    }

    #[test]
    fn long_lines_are_cut_and_only_a_few_are_quoted() {
        let text = format!("{}\nx\nx\nx\nx\n", "x".repeat(500));
        let hit = score("a.md", &text, &terms("x")).unwrap();
        assert_eq!(hit.lines.len(), SNIPPETS_PER_NOTE);
        assert_eq!(hit.lines[0].chars().count(), SNIPPET_CHARS + 1);
    }
}
