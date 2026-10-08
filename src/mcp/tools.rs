//! The MCP tools.
//!
//! Every tool acts as the member whose token made the request. The auth
//! middleware has already verified that token and left the member's DID in
//! the request's extensions; a tool reads the DID from there and never sees
//! the token.

use axum::http::request::Parts;
use rmcp::{
    handler::server::{router::tool::ToolRouter, tool::Extension, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router, ErrorData, ServerHandler,
};
use serde::Deserialize;
use serde_json::json;

use super::notes::{NoteError, Notes};
use super::search;
use crate::auth::Did;
use crate::authz::Authz;

const DEFAULT_SEARCH_LIMIT: usize = 20;
const MAX_SEARCH_LIMIT: usize = 50;

#[derive(Clone)]
pub struct NotesServer {
    authz: Authz,
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ListNotes {
    /// Vault name. May be left out when you have exactly one vault.
    vault: Option<String>,
    /// Folder to list, such as "Projects/2026". Leave out for the top level.
    path: Option<String>,
    /// Also list everything inside the folders found. Defaults to false.
    recursive: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ReadNote {
    /// Vault name. May be left out when you have exactly one vault.
    vault: Option<String>,
    /// Path of the note, such as "Projects/plan.md".
    path: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct SearchNotes {
    /// Vault name. May be left out when you have exactly one vault.
    vault: Option<String>,
    /// Words to look for. A note matches when it contains all of them, in its
    /// text or its path, in any letter case.
    query: String,
    /// The most notes to return. Defaults to 20, at most 50.
    limit: Option<usize>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct CreateNote {
    /// Vault name. May be left out when you have exactly one vault.
    vault: Option<String>,
    /// Path for the new note, ending in ".md", such as "Projects/plan.md".
    /// Folders on the way that do not exist are created.
    path: String,
    /// The note's markdown.
    content: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct EditNote {
    /// Vault name. May be left out when you have exactly one vault.
    vault: Option<String>,
    /// Path of the note, such as "Projects/plan.md".
    path: String,
    /// The exact text to replace. It must appear in the note, and only once
    /// unless replace_all is set, so include enough around it to be unique.
    old_text: String,
    /// The text to put in its place. Empty removes old_text.
    new_text: String,
    /// Replace every place old_text appears. Defaults to false.
    replace_all: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct AppendNote {
    /// Vault name. May be left out when you have exactly one vault.
    vault: Option<String>,
    /// Path of the note, such as "Projects/plan.md".
    path: String,
    /// The text to add. It starts on a new line.
    text: String,
}

fn said(text: impl Into<String>) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

fn listed(value: serde_json::Value) -> Result<CallToolResult, ErrorData> {
    said(serde_json::to_string_pretty(&value).unwrap_or_default())
}

/// A refusal goes back as a tool result the model can read and act on. A
/// fault of ours is logged and reported as an error without detail.
fn failed(e: NoteError) -> Result<CallToolResult, ErrorData> {
    match e {
        NoteError::Refused(why) => Ok(CallToolResult::error(vec![ContentBlock::text(why)])),
        NoteError::Internal(e) => {
            tracing::error!(error = %e, "a tool failed");
            Err(ErrorData::internal_error("the relay could not do that", None))
        }
    }
}

/// The member the request was authenticated as.
fn caller(parts: &Parts) -> Result<Did, ErrorData> {
    parts
        .extensions
        .get::<Did>()
        .cloned()
        // Unreachable behind the middleware. Refused rather than assumed.
        .ok_or_else(|| ErrorData::invalid_request("not authenticated", None))
}

#[tool_router]
impl NotesServer {
    pub fn new(authz: Authz) -> Self {
        Self {
            authz,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "List your vaults. A vault is a separate collection of notes.",
        annotations(title = "List vaults", read_only_hint = true)
    )]
    async fn list_vaults(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let did = caller(&parts)?;
        match self.authz.list_vaults(&did).await {
            Ok(vaults) => listed(json!(vaults
                .iter()
                .map(|vault| json!({
                    "name": vault.name,
                    "created_at": vault.created_at,
                    "last_change_at": vault.last_change_at,
                }))
                .collect::<Vec<_>>())),
            Err(e) => failed(NoteError::Internal(e)),
        }
    }

    #[tool(
        description = "List the notes and folders in a vault, or in one folder of it.",
        annotations(title = "List notes", read_only_hint = true)
    )]
    async fn list_notes(
        &self,
        Parameters(args): Parameters<ListNotes>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let did = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            did: &did,
        };
        let found = async {
            let (root, _) = notes.vault(args.vault.as_deref()).await?;
            notes
                .list(
                    &root,
                    args.path.as_deref().unwrap_or_default(),
                    args.recursive.unwrap_or(false),
                )
                .await
        };
        match found.await {
            Ok(found) => listed(json!(found
                .iter()
                .map(|item| json!({
                    "path": item.path,
                    "type": if item.is_folder { "folder" } else { "note" },
                }))
                .collect::<Vec<_>>())),
            Err(e) => failed(e),
        }
    }

    #[tool(
        description = "Read a note's markdown.",
        annotations(title = "Read note", read_only_hint = true)
    )]
    async fn read_note(
        &self,
        Parameters(args): Parameters<ReadNote>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let did = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            did: &did,
        };
        let text = async {
            let (root, _) = notes.vault(args.vault.as_deref()).await?;
            notes.read(&root, &args.path).await
        };
        match text.await {
            Ok(text) => said(text),
            Err(e) => failed(e),
        }
    }

    #[tool(
        description = "Search the text of every note in a vault. Returns the matching notes' \
                       paths with the lines that matched.",
        annotations(title = "Search notes", read_only_hint = true)
    )]
    async fn search_notes(
        &self,
        Parameters(args): Parameters<SearchNotes>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let did = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            did: &did,
        };
        let limit = args
            .limit
            .unwrap_or(DEFAULT_SEARCH_LIMIT)
            .clamp(1, MAX_SEARCH_LIMIT);
        let hits = async {
            let (root, _) = notes.vault(args.vault.as_deref()).await?;
            search::search(&notes, &root, &args.query, limit).await
        };
        match hits.await {
            Ok(hits) => listed(json!(hits
                .iter()
                .map(|hit| json!({
                    "path": hit.path,
                    "matches": hit.count,
                    "lines": hit.lines,
                }))
                .collect::<Vec<_>>())),
            Err(e) => failed(e),
        }
    }

    #[tool(
        description = "Create a new note. Fails if something already exists at the path.",
        annotations(title = "Create note", read_only_hint = false, destructive_hint = false)
    )]
    async fn create_note(
        &self,
        Parameters(args): Parameters<CreateNote>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let did = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            did: &did,
        };
        let created = async {
            let (root, vault) = notes.vault(args.vault.as_deref()).await?;
            let path = notes.create(&root, &args.path, &args.content).await?;
            Ok((vault, path))
        };
        match created.await {
            Ok((vault, path)) => said(format!("Created {path} in {vault}.")),
            Err(e) => failed(e),
        }
    }

    #[tool(
        description = "Change part of a note by replacing one piece of its text with another. \
                       Read the note first so old_text matches it exactly.",
        annotations(title = "Edit note", read_only_hint = false, destructive_hint = true)
    )]
    async fn edit_note(
        &self,
        Parameters(args): Parameters<EditNote>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let did = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            did: &did,
        };
        let path = args.path.clone();
        let edited = async {
            let (root, _) = notes.vault(args.vault.as_deref()).await?;
            notes
                .edit(
                    &root,
                    &args.path,
                    args.old_text,
                    args.new_text,
                    args.replace_all.unwrap_or(false),
                )
                .await
        };
        match edited.await {
            Ok(1) => said(format!("Edited {path}.")),
            Ok(n) => said(format!("Edited {path} in {n} places.")),
            Err(e) => failed(e),
        }
    }

    #[tool(
        description = "Add text to the end of a note.",
        annotations(title = "Append to note", read_only_hint = false, destructive_hint = false)
    )]
    async fn append_note(
        &self,
        Parameters(args): Parameters<AppendNote>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let did = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            did: &did,
        };
        let path = args.path.clone();
        let appended = async {
            let (root, _) = notes.vault(args.vault.as_deref()).await?;
            notes.append(&root, &args.path, args.text).await
        };
        match appended.await {
            Ok(()) => said(format!("Appended to {path}.")),
            Err(e) => failed(e),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for NotesServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "scn-sync-relay",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Your Obsidian notes on the Shared Computer Network. Notes are markdown files \
                 addressed by path inside a vault. Changes made here appear in Obsidian on \
                 your devices, and changes made there appear here.",
            )
    }
}
