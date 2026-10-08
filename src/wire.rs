//! Just enough of the sync protocol to know which document a frame is about.
//!
//! Each frame is a CBOR map with string keys. The filter needs four of them:
//! `type`, `senderId`, `targetId` and `documentId`. Everything else is skipped
//! unread and the frame is forwarded, or not, as the bytes it arrived as.
//!
//! samod has its own decoder for these frames and does not export it. This
//! reader has to agree with that one about which document a frame names,
//! because the filter decides on this reading and samod acts on its own. A
//! frame this reader cannot make sense of is never forwarded.

use std::str::FromStr;

use samod::DocumentId;

#[derive(Debug, PartialEq)]
pub struct Envelope {
    pub kind: String,
    pub sender_id: Option<String>,
    pub target_id: Option<String>,
    pub document_id: Option<DocumentId>,
}

/// Read a frame's envelope, or `None` if it is not one this reader accepts.
pub fn read(frame: &[u8]) -> Option<Envelope> {
    let mut decoder = minicbor::Decoder::new(frame);
    let len = decoder.map().ok()??;

    let mut kind = None;
    let mut sender_id = None;
    let mut target_id = None;
    let mut document_id = None;

    for _ in 0..len {
        match decoder.str().ok()? {
            "type" => set_once(&mut kind, decoder.str().ok()?.to_string())?,
            "senderId" => set_once(&mut sender_id, decoder.str().ok()?.to_string())?,
            "targetId" => set_once(&mut target_id, decoder.str().ok()?.to_string())?,
            "documentId" => {
                // The JS client sends the ID as a string; bytes are accepted
                // because samod accepts them.
                let id = if decoder.probe().str().is_ok() {
                    DocumentId::from_str(decoder.str().ok()?).ok()?
                } else {
                    DocumentId::try_from(decoder.bytes().ok()?.to_vec()).ok()?
                };
                set_once(&mut document_id, id)?;
            }
            _ => decoder.skip().ok()?,
        }
    }

    Some(Envelope {
        kind: kind?,
        sender_id,
        target_id,
        document_id,
    })
}

/// A key that appears twice makes the frame unreadable.
///
/// samod keeps the last value of a repeated key. A reader that kept the first
/// would check one document and let samod act on another.
fn set_once<T>(slot: &mut Option<T>, value: T) -> Option<()> {
    if slot.is_some() {
        return None;
    }
    *slot = Some(value);
    Some(())
}

/// A `doc-unavailable` frame: what a peer is told about a document it asked
/// for and may not have. It is the same answer a document that does not exist
/// gets, so the two cannot be told apart.
pub fn doc_unavailable(sender_id: &str, target_id: &str, document_id: &DocumentId) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    // Writing to a Vec cannot fail.
    let _ = encoder
        .map(4)
        .and_then(|e| e.str("type")?.str("doc-unavailable"))
        .and_then(|e| e.str("senderId")?.str(sender_id))
        .and_then(|e| e.str("targetId")?.str(target_id))
        .and_then(|e| e.str("documentId")?.str(&document_id.to_string()));
    encoder.into_writer()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const CLIENT: &str = "client-peer";
    pub const RELAY: &str = "relay-peer";

    /// A frame from the client to the relay, shaped as samod and the JS client
    /// send them: the envelope plus a payload the filter never reads.
    pub fn frame(kind: &str, document_id: Option<&DocumentId>) -> Vec<u8> {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.map(if document_id.is_some() { 5 } else { 4 }).unwrap();
        e.str("type").unwrap().str(kind).unwrap();
        e.str("senderId").unwrap().str(CLIENT).unwrap();
        e.str("targetId").unwrap().str(RELAY).unwrap();
        if let Some(id) = document_id {
            e.str("documentId").unwrap().str(&id.to_string()).unwrap();
        }
        e.str("data").unwrap().bytes(&[1, 2, 3]).unwrap();
        e.into_writer()
    }

    pub fn doc_id(n: u8) -> DocumentId {
        DocumentId::try_from(vec![n; 16]).unwrap()
    }

    #[test]
    fn reads_the_envelope_and_skips_the_rest() {
        let id = doc_id(1);
        assert_eq!(
            read(&frame("sync", Some(&id))),
            Some(Envelope {
                kind: "sync".to_string(),
                sender_id: Some(CLIENT.to_string()),
                target_id: Some(RELAY.to_string()),
                document_id: Some(id),
            })
        );
        assert_eq!(read(&frame("leave", None)).unwrap().document_id, None);
    }

    #[test]
    fn reads_a_document_id_sent_as_bytes() {
        let id = doc_id(2);
        let mut e = minicbor::Encoder::new(Vec::new());
        e.map(2).unwrap();
        e.str("type").unwrap().str("sync").unwrap();
        e.str("documentId").unwrap().bytes(id.as_bytes()).unwrap();
        assert_eq!(read(&e.into_writer()).unwrap().document_id, Some(id));
    }

    #[test]
    fn reads_back_its_own_doc_unavailable() {
        let id = doc_id(3);
        assert_eq!(
            read(&doc_unavailable(RELAY, CLIENT, &id)),
            Some(Envelope {
                kind: "doc-unavailable".to_string(),
                sender_id: Some(RELAY.to_string()),
                target_id: Some(CLIENT.to_string()),
                document_id: Some(id),
            })
        );
    }

    #[test]
    fn refuses_a_repeated_key() {
        let (allowed, victim) = (doc_id(4), doc_id(5));
        let mut e = minicbor::Encoder::new(Vec::new());
        e.map(3).unwrap();
        e.str("type").unwrap().str("sync").unwrap();
        e.str("documentId").unwrap().str(&allowed.to_string()).unwrap();
        e.str("documentId").unwrap().str(&victim.to_string()).unwrap();
        assert_eq!(read(&e.into_writer()), None);
    }

    #[test]
    fn refuses_what_it_cannot_parse() {
        let mut no_type = minicbor::Encoder::new(Vec::new());
        no_type.map(1).unwrap();
        no_type.str("senderId").unwrap().str(CLIENT).unwrap();

        let mut bad_id = minicbor::Encoder::new(Vec::new());
        bad_id.map(2).unwrap();
        bad_id.str("type").unwrap().str("sync").unwrap();
        bad_id.str("documentId").unwrap().str("not an id").unwrap();

        let mut not_a_map = minicbor::Encoder::new(Vec::new());
        not_a_map.array(1).unwrap().str("sync").unwrap();

        let truncated = &frame("sync", Some(&doc_id(6)))[..12];

        for bytes in [
            &no_type.into_writer()[..],
            &bad_id.into_writer()[..],
            &not_a_map.into_writer()[..],
            truncated,
            &[],
        ] {
            assert_eq!(read(bytes), None);
        }
    }
}
