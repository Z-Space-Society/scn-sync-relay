//! The wall between a connection and the repo.
//!
//! samod has no way to refuse a peer: one that names a document ID gets the
//! document and can write to it, and a frame for an unknown ID creates that
//! document. So the relay does not hand samod the websocket. It hands samod a
//! transport of its own and stands in the middle, passing each frame in either
//! direction only if the connection's DID may open the document it names.
//!
//! The filter also ends the connection when the token that opened it expires.
//! samod has no call to close one connection, and a websocket can otherwise
//! stay open for days after its owner has left the network.

use std::convert::Infallible;
use std::time::{Duration, SystemTime};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures::{channel::mpsc, SinkExt, StreamExt};
use samod::{AcceptorHandle, Transport};

use crate::auth::Did;
use crate::authz::Authz;
use crate::wire;

/// Frames queued between the websocket and samod in each direction before the
/// faster side has to wait.
const BUFFER: usize = 64;

/// RFC 6455 "policy violation": the nearest standard code to "your token ran
/// out". The client reconnects with a fresh one.
const CLOSE_POLICY: u16 = 1008;

pub struct Filter {
    authz: Authz,
    did: Did,
}

#[derive(Debug, PartialEq)]
pub enum Inbound {
    /// Hand the frame to samod.
    Pass,
    /// Discard the frame and say nothing.
    Drop,
    /// Discard the frame and send this one back.
    Deny(Vec<u8>),
}

impl Filter {
    pub fn new(authz: Authz, did: Did) -> Self {
        Self { authz, did }
    }

    /// Decide what to do with a frame from the peer.
    pub async fn inbound(&self, frame: &[u8]) -> Inbound {
        let Some(envelope) = wire::read(frame) else {
            tracing::warn!(did = %self.did, "dropping an unreadable frame");
            return Inbound::Drop;
        };

        match envelope.kind.as_str() {
            "join" | "leave" | "error" => Inbound::Pass,

            "request" | "sync" | "ephemeral" | "doc-unavailable" => {
                let Some(doc) = envelope.document_id else {
                    tracing::warn!(did = %self.did, kind = %envelope.kind, "dropping a frame with no document ID");
                    return Inbound::Drop;
                };

                // A document nobody has sent before belongs to whoever sends
                // it first. If that cannot be recorded, nobody gets it.
                let allowed = match self.authz.record_creator(&doc, &self.did).await {
                    Ok(_) => self.authz.may_open(&self.did, &doc),
                    Err(e) => {
                        tracing::error!(did = %self.did, %doc, error = %e, "could not record a document's creator");
                        false
                    }
                };
                if allowed {
                    return Inbound::Pass;
                }

                // Addressed back the way the frame came. No log line: a peer
                // asking for a document it may not have is ordinary, and is
                // answered exactly as a document that does not exist.
                Inbound::Deny(wire::doc_unavailable(
                    envelope.target_id.as_deref().unwrap_or_default(),
                    envelope.sender_id.as_deref().unwrap_or_default(),
                    &doc,
                ))
            }

            // What other peers hold is not this peer's to announce or learn.
            "remote-subscription-change" | "remote-heads-changed" => Inbound::Drop,

            kind => {
                tracing::warn!(did = %self.did, kind, "dropping a frame of an unexpected type");
                Inbound::Drop
            }
        }
    }

    /// May this frame from samod go to the peer?
    ///
    /// The second wall. The inbound check should mean samod never has a
    /// reason to send this peer a document it may not open; this is what holds
    /// if that turns out to be wrong.
    pub fn outbound(&self, frame: &[u8]) -> bool {
        let Some(envelope) = wire::read(frame) else {
            tracing::warn!(did = %self.did, "withholding an unreadable outbound frame");
            return false;
        };
        match envelope.document_id {
            Some(doc) => {
                let allowed = self.authz.may_open(&self.did, &doc);
                if !allowed {
                    tracing::warn!(did = %self.did, %doc, kind = %envelope.kind, "withholding a frame for a document this peer may not open");
                }
                allowed
            }
            None => true,
        }
    }
}

/// Serve one connection through the filter until either side ends it or its
/// token expires.
pub async fn run(
    socket: WebSocket,
    acceptor: &AcceptorHandle,
    filter: Filter,
    expires_at: Option<SystemTime>,
) {
    let (mut ws_out, mut ws_in) = socket.split();
    let (mut to_samod, samod_in) = mpsc::channel::<Result<Vec<u8>, Infallible>>(BUFFER);
    let (samod_out, mut from_samod) = mpsc::channel::<Vec<u8>>(BUFFER);
    // Answers the inbound side wants sent. They share the websocket's write
    // half with samod's frames, so they queue for the side that owns it.
    let (mut reply, mut replies) = mpsc::channel::<Vec<u8>>(BUFFER);

    if acceptor.accept(Transport::new(samod_in, samod_out)).is_err() {
        tracing::warn!(did = %filter.did, "repo stopped; dropping connection");
        return;
    }
    tracing::info!(did = %filter.did, "peer connected");

    // Each direction runs on its own, so a full queue one way never stops the
    // other and the two cannot wait on each other.
    let inbound = async {
        while let Some(Ok(message)) = ws_in.next().await {
            let frame = match message {
                Message::Binary(frame) => frame,
                Message::Ping(_) | Message::Pong(_) => continue,
                // The protocol is binary. Text or a close ends the connection.
                Message::Text(_) | Message::Close(_) => break,
            };
            let sent = match filter.inbound(&frame).await {
                Inbound::Pass => to_samod.send(Ok(frame.into())).await.is_ok(),
                Inbound::Drop => true,
                Inbound::Deny(answer) => reply.send(answer).await.is_ok(),
            };
            if !sent {
                break;
            }
        }
    };

    let outbound = async {
        let expired = async {
            match expires_at {
                Some(at) => {
                    let left = at.duration_since(SystemTime::now()).unwrap_or(Duration::ZERO);
                    tokio::time::sleep(left).await
                }
                None => std::future::pending().await,
            }
        };
        tokio::pin!(expired);

        loop {
            let frame = tokio::select! {
                _ = &mut expired => {
                    tracing::info!(did = %filter.did, "token expired; closing connection");
                    let _ = ws_out
                        .send(Message::Close(Some(CloseFrame {
                            code: CLOSE_POLICY,
                            reason: "token expired".into(),
                        })))
                        .await;
                    break;
                }
                frame = from_samod.next() => match frame {
                    Some(frame) if filter.outbound(&frame) => frame,
                    Some(_) => continue,
                    None => break,
                },
                answer = replies.next() => match answer {
                    Some(answer) => answer,
                    None => break,
                },
            };
            if ws_out.send(Message::Binary(frame.into())).await.is_err() {
                break;
            }
        }
    };

    // Whichever direction ends first ends the connection. Dropping samod's
    // inbound stream is what makes it let go of its side.
    tokio::select! {
        _ = inbound => {}
        _ = outbound => {}
    }
    tracing::info!(did = %filter.did, "peer disconnected");
}

#[cfg(test)]
mod tests {
    use super::*;

    use automerge::Automerge;
    use sqlx::PgPool;

    use crate::authz::tests::{did, open};
    use crate::wire::tests::{doc_id, frame, CLIENT, RELAY};

    fn denied(doc: &samod::DocumentId) -> Inbound {
        Inbound::Deny(wire::doc_unavailable(RELAY, CLIENT, doc))
    }

    #[sqlx::test(migrations = false)]
    async fn frames_for_a_members_own_document_pass_both_ways(pool: PgPool) {
        let (authz, _repo) = open(&pool).await;
        let alice = Filter::new(authz.clone(), did("alice"));
        let doc = doc_id(1);

        for kind in ["sync", "request", "ephemeral", "doc-unavailable"] {
            assert_eq!(alice.inbound(&frame(kind, Some(&doc))).await, Inbound::Pass);
            assert!(alice.outbound(&frame(kind, Some(&doc))));
        }
    }

    #[sqlx::test(migrations = false)]
    async fn the_first_sender_of_a_new_document_becomes_its_creator(pool: PgPool) {
        let (authz, _repo) = open(&pool).await;
        let alice = Filter::new(authz.clone(), did("alice"));
        let bob = Filter::new(authz.clone(), did("bob"));
        let doc = doc_id(2);

        assert_eq!(authz.creator_of(&doc), None);
        assert_eq!(alice.inbound(&frame("sync", Some(&doc))).await, Inbound::Pass);
        assert_eq!(authz.creator_of(&doc), Some(did("alice")));

        assert_eq!(bob.inbound(&frame("sync", Some(&doc))).await, denied(&doc));
        assert_eq!(authz.creator_of(&doc), Some(did("alice")));
    }

    #[sqlx::test(migrations = false)]
    async fn another_members_document_is_denied_and_withheld(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let vault = authz.create_vault(&did("alice"), "Notes").await.unwrap();
        let root = vault.root_doc_id.parse().unwrap();
        let note = repo.create(Automerge::new()).await.unwrap();
        let note = note.document_id();
        authz.record_creator(note, &did("alice")).await.unwrap();
        let bob = Filter::new(authz.clone(), did("bob"));

        for doc in [&root, note] {
            for kind in ["sync", "request", "ephemeral", "doc-unavailable"] {
                assert_eq!(bob.inbound(&frame(kind, Some(doc))).await, denied(doc));
                assert!(!bob.outbound(&frame(kind, Some(doc))));
            }
        }
    }

    #[sqlx::test(migrations = false)]
    async fn frames_about_no_document_follow_the_table(pool: PgPool) {
        let (authz, _repo) = open(&pool).await;
        let alice = Filter::new(authz.clone(), did("alice"));
        let doc = doc_id(3);

        for kind in ["join", "leave", "error"] {
            assert_eq!(alice.inbound(&frame(kind, None)).await, Inbound::Pass);
        }
        for kind in ["remote-subscription-change", "remote-heads-changed"] {
            assert_eq!(alice.inbound(&frame(kind, Some(&doc))).await, Inbound::Drop);
        }
        // A type the relay never expects from a client, a frame that needs a
        // document ID and has none, and bytes that are not a frame.
        assert_eq!(alice.inbound(&frame("peer", None)).await, Inbound::Drop);
        assert_eq!(alice.inbound(&frame("sync", None)).await, Inbound::Drop);
        assert_eq!(alice.inbound(b"not cbor").await, Inbound::Drop);
        // None of those made her the creator of anything.
        assert_eq!(authz.creator_of(&doc), None);

        assert!(alice.outbound(&frame("peer", None)));
        assert!(!alice.outbound(b"not cbor"));
    }
}
