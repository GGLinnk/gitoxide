//! Emit the server's acknowledgement section for a v2 fetch response.
//!
//! After parsing the client's [`super::FetchRequest`], the server may
//! respond with an `acknowledgments` section before the pack:
//!
//! ```text
//! acknowledgments LF
//! ACK <oid> LF                (optional, for each have the server already has)
//! NAK LF                      (when no have matched)
//! ready LF                    (v2 token indicating the server will send the pack)
//! ```
//!
//! This module provides two emitters that produce ordered pkt-line
//! payloads:
//!
//! - [`emit_section_from_acks`] - Branch B of the v2 grammar, consuming
//!   the full [`Acknowledgments`] struct (commons + optional trailer).
//! - [`emit_section_from_oids`] - Branch A of the v2 grammar
//!   (mid-negotiation, no pack follows), consuming only the common oids;
//!   the `ready` trailer is type-unrepresentable here because emitting
//!   it without a following pack would be a protocol violation.
//!
//! Pack-streaming itself is out of scope.

use bstr::{BString, ByteVec};

use crate::wire_types::{AckTrailer, Acknowledgments};

/// Emit the `acknowledgments` section of a v2 Branch-B fetch response
/// (with packfile following) as ordered LF-terminated byte payloads.
///
/// The first line is the section header `acknowledgments`; each entry
/// in `acks.common_oids` becomes one `ACK <oid>` pkt-line; if
/// `acks.trailer` is `Some(AckTrailer::Ready)` a final `ready` line is
/// appended. Empty `common_oids` with no trailer emits a single `NAK`
/// body line per the grammar alternation `(nak | *ack)`. The caller
/// frames each returned line as a pkt-line and terminates the section
/// with a v2 delim-pkt before the next section or a flush-pkt.
pub fn emit_section_from_acks(acks: &Acknowledgments) -> Vec<BString> {
    let mut lines = Vec::with_capacity(2 + acks.common_oids.len());
    lines.push(BString::from("acknowledgments\n"));
    if acks.common_oids.is_empty() && acks.trailer.is_none() {
        lines.push(BString::from("NAK\n"));
    } else {
        for oid in &acks.common_oids {
            lines.push(ack_line(oid));
        }
        if let Some(trailer) = acks.trailer {
            match trailer {
                AckTrailer::Ready => lines.push(BString::from("ready\n")),
            }
        }
    }
    lines
}

/// Emit the `acknowledgments` section of a v2 Branch-A fetch response
/// (no packfile follows, mid-negotiation) as ordered LF-terminated
/// byte payloads.
///
/// The first line is the section header; each entry in `common_oids`
/// becomes one `ACK <oid>` pkt-line. Empty `common_oids` emits a
/// single `NAK` body line. No trailer codepath exists - emitting
/// `ready` without a pack following is a protocol violation.
pub fn emit_section_from_oids(common_oids: &[gix_hash::ObjectId]) -> Vec<BString> {
    let mut lines = Vec::with_capacity(2 + common_oids.len());
    lines.push(BString::from("acknowledgments\n"));
    if common_oids.is_empty() {
        lines.push(BString::from("NAK\n"));
    } else {
        for oid in common_oids {
            lines.push(ack_line(oid));
        }
    }
    lines
}

/// Emit the v2 `packfile` section header line.
///
/// After this line the server streams the pack bytes via side-band (if
/// negotiated) or verbatim. This helper only emits the section header;
/// framing the pack itself is the caller's responsibility.
pub fn emit_packfile_header() -> BString {
    BString::from("packfile\n")
}

fn ack_line(oid: &gix_hash::ObjectId) -> BString {
    let mut line = BString::from("ACK ");
    line.push_str(oid.to_hex().to_string());
    line.push(b'\n');
    line
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    #[test]
    fn empty_acknowledgments_emit_header_plus_nak() {
        let lines = emit_section_from_acks(&Acknowledgments::default());
        assert_eq!(lines, vec![BString::from("acknowledgments\n"), BString::from("NAK\n")]);
    }

    #[test]
    fn single_ack_keeps_the_header_and_omits_nak() {
        let lines = emit_section_from_acks(&Acknowledgments {
            common_oids: vec![oid("1111111111111111111111111111111111111111")],
            trailer: None,
        });
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "acknowledgments\n");
        assert_eq!(lines[1], "ACK 1111111111111111111111111111111111111111\n");
    }

    #[test]
    fn ready_trailer_appends_ready_terminator() {
        let lines = emit_section_from_acks(&Acknowledgments {
            common_oids: vec![oid("1111111111111111111111111111111111111111")],
            trailer: Some(AckTrailer::Ready),
        });
        assert_eq!(lines.last().expect("has lines"), "ready\n");
    }

    #[test]
    fn from_oids_empty_emits_nak() {
        let lines = emit_section_from_oids(&[]);
        assert_eq!(lines, vec![BString::from("acknowledgments\n"), BString::from("NAK\n")]);
    }

    #[test]
    fn from_oids_emits_one_ack_per_entry() {
        let lines = emit_section_from_oids(&[
            oid("1111111111111111111111111111111111111111"),
            oid("2222222222222222222222222222222222222222"),
        ]);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "acknowledgments\n");
        assert_eq!(lines[1], "ACK 1111111111111111111111111111111111111111\n");
        assert_eq!(lines[2], "ACK 2222222222222222222222222222222222222222\n");
    }

    #[test]
    fn packfile_header_is_a_section_marker() {
        assert_eq!(emit_packfile_header(), "packfile\n");
    }
}
