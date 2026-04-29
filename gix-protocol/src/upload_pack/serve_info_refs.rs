//! Framing helpers for writing an upload-pack advertisement as pkt-lines.
//!
//! These helpers sit above [`super::advertisement`]'s pure-data emitters
//! and turn an ordered `Vec<BString>` of LF-terminated payloads into a
//! complete pkt-line stream suitable for a smart-HTTP `info/refs`
//! response body.

use std::io::Write;

use bstr::BString;

use super::advertisement::{self, AdvertisedRef};
use super::options::{Options, OptionsV2};

/// Write a v0 / v1 upload-pack advertisement to `out`.
///
/// Emits each ref line as a pkt-line, then a terminating flush-pkt. The
/// caller is responsible for any transport-level prelude (for smart-HTTP:
/// the `# service=git-upload-pack\n` banner followed by a flush-pkt,
/// written *before* this call).
pub fn write_v1<W: Write>(out: &mut W, refs: &[AdvertisedRef], options: &Options) -> std::io::Result<()> {
    let lines = advertisement::emit_v1(refs, options);
    write_lines_and_flush(out, &lines)
}

/// Write a v2 upload-pack advertisement to `out`.
///
/// Emits the `version 2` header plus one capability token per pkt-line,
/// then a terminating flush-pkt.
pub fn write_v2<W: Write>(out: &mut W, options: &OptionsV2) -> std::io::Result<()> {
    let lines = advertisement::emit_v2(options);
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
    fn v1_ends_with_flush_pkt() {
        let refs = vec![AdvertisedRef {
            object: oid("1111111111111111111111111111111111111111"),
            name: BString::from("refs/heads/main"),
            peeled: None,
        }];
        let mut buf = Vec::new();
        write_v1(&mut buf, &refs, &Options::default()).expect("write_v1");
        assert!(buf.ends_with(b"0000"), "advertisement ends with flush-pkt `0000`");
    }

    #[test]
    fn v2_starts_with_framed_version_header() {
        let mut buf = Vec::new();
        write_v2(&mut buf, &OptionsV2::default()).expect("write_v2");
        // Every pkt-line starts with 4 hex chars describing the length. The
        // very first packet must be the `version 2\n` line, so the payload
        // bytes `version 2\n` appear immediately after the 4-byte length.
        let first_length = std::str::from_utf8(&buf[..4]).expect("ascii length");
        let len = u16::from_str_radix(first_length, 16).expect("hex length");
        assert_eq!(len as usize, 4 + "version 2\n".len());
        assert!(buf[4..].starts_with(b"version 2\n"));
        assert!(buf.ends_with(b"0000"));
    }
}
