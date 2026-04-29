//! Framing helpers for writing a receive-pack advertisement as pkt-lines.
//!
//! Symmetrical to [`crate::upload_pack::serve_info_refs`]: the same
//! framing shape (length-prefixed pkt-lines followed by a flush-pkt),
//! but emitting the push-oriented capability set from
//! [`super::advertisement::Options`].

use std::io::Write;

use bstr::BString;

use super::advertisement::{self, AdvertisedRef, Options};

/// Write a v0 / v1 receive-pack advertisement to `out`.
///
/// Emits each ref line as a pkt-line, then a terminating flush-pkt. The
/// caller is responsible for any transport-level prelude (for smart-HTTP:
/// the `# service=git-receive-pack\n` banner followed by a flush-pkt,
/// written *before* this call).
pub fn write_v1<W: Write>(out: &mut W, refs: &[AdvertisedRef], options: &Options) -> std::io::Result<()> {
    let lines = advertisement::emit_v1(refs, options);
    write_lines_and_flush(out, &lines)
}

fn write_lines_and_flush<W: Write>(out: &mut W, lines: &[BString]) -> std::io::Result<()> {
    use gix_packetline::blocking_io::encode;
    for line in lines {
        encode::data_to_write(line.as_slice(), &mut *out)?;
    }
    encode::flush_to_write(out)?;
    Ok(())
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    #[test]
    fn v1_ends_with_flush_pkt_and_carries_push_capabilities() {
        let refs = vec![AdvertisedRef {
            object: oid("1111111111111111111111111111111111111111"),
            name: BString::from("refs/heads/main"),
            peeled: None,
        }];
        let mut buf = Vec::new();
        write_v1(&mut buf, &refs, &Options::default()).expect("write_v1");
        assert!(buf.ends_with(b"0000"));
        // The capability list in the first line after NUL should contain
        // push-specific capabilities, not upload-pack ones.
        assert!(
            buf.windows(16).any(|w| w == b"report-status-v2"),
            "receive-pack advertisement should carry report-status-v2"
        );
        assert!(
            !buf.windows(18).any(|w| w == b"multi_ack_detailed"),
            "receive-pack advertisement must not carry fetch-only multi_ack_detailed"
        );
    }
}
