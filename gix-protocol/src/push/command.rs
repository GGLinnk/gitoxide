//! Serialization of reference-update command lines for the push side of the
//! git pack protocol.
//!
//! Each push update is a single line of the form
//!
//! ```text
//! <old-oid> SP <new-oid> SP <refname> [NUL capability-list] LF
//! ```
//!
//! where the NUL-separated capability list is present only on the first line
//! of an update-request block. Subsequent lines carry no capabilities. All
//! lines are LF-terminated; pkt-line framing is added by the transport layer.
//!
//! See the [pack protocol reference][spec] for the full grammar.
//!
//! [spec]: https://git-scm.com/docs/pack-protocol#_reference_update_request_and_packfile_transfer

use std::io::Write as _;

use bstr::BString;

/// A single reference-update instruction sent to the server as part of a push.
///
/// The wire format does not distinguish between the three update kinds by a
/// keyword; the distinction is made solely by which of `old_id` / `new_id` is
/// the all-zero OID:
///
/// - `old_id` is the all-zero OID for ref **creation**.
/// - `new_id` is the all-zero OID for ref **deletion**.
/// - Otherwise the command is a regular **update**.
///
/// A `Command` with both `old_id` and `new_id` set to the zero OID is
/// syntactically valid but semantically a no-op; callers are expected to
/// filter such entries before emitting them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Command {
    /// The OID the ref currently points to, or the all-zero OID to request
    /// creation.
    pub old_id: gix_hash::ObjectId,
    /// The OID the ref should point to after the push, or the all-zero OID to
    /// request deletion.
    pub new_id: gix_hash::ObjectId,
    /// The fully-qualified ref name the server should update, e.g.
    /// `refs/heads/main`. No validation is performed here; it is expected to
    /// have been validated with `gix-validate` by the caller.
    pub refname: BString,
}

impl Command {
    /// Return true if this command creates a new ref (zero `old_id`).
    pub fn is_create(&self) -> bool {
        self.old_id.is_null()
    }

    /// Return true if this command deletes an existing ref (zero `new_id`).
    pub fn is_delete(&self) -> bool {
        self.new_id.is_null()
    }

    /// Return true if this command updates an existing ref to a new tip.
    pub fn is_update(&self) -> bool {
        !self.is_create() && !self.is_delete()
    }

    /// Append this command to `out` as a line *without* capabilities.
    ///
    /// Suitable for every line after the first in an update-request block.
    /// The written bytes include the trailing LF.
    pub fn write_to(&self, out: &mut Vec<u8>) -> std::io::Result<()> {
        write!(out, "{} {} ", self.old_id.to_hex(), self.new_id.to_hex())?;
        out.extend_from_slice(self.refname.as_slice());
        out.push(b'\n');
        Ok(())
    }

    /// Append this command to `out` as the first line of an update-request
    /// block, with the NUL-separated capability list appended.
    ///
    /// Capabilities are space-joined after a single NUL byte. No validation
    /// is performed against a server advertisement; the caller is expected to
    /// filter the set ahead of time.
    ///
    /// The written bytes include the trailing LF.
    pub fn write_first_line_to<S: AsRef<str>>(&self, out: &mut Vec<u8>, capabilities: &[S]) -> std::io::Result<()> {
        write!(out, "{} {} ", self.old_id.to_hex(), self.new_id.to_hex())?;
        out.extend_from_slice(self.refname.as_slice());
        out.push(0);
        let mut first = true;
        for cap in capabilities {
            if !first {
                out.push(b' ');
            }
            out.extend_from_slice(cap.as_ref().as_bytes());
            first = false;
        }
        out.push(b'\n');
        Ok(())
    }

    /// Allocating convenience over [`Self::write_to`].
    pub fn to_line(&self) -> BString {
        let mut buf = Vec::with_capacity(self.encoded_size_hint(0));
        self.write_to(&mut buf).expect("writing to Vec cannot fail");
        buf.into()
    }

    /// Allocating convenience over [`Self::write_first_line_to`].
    pub fn to_first_line<S: AsRef<str>>(&self, capabilities: &[S]) -> BString {
        let caps_len: usize =
            capabilities.iter().map(|c| c.as_ref().len()).sum::<usize>() + capabilities.len().saturating_sub(1); // inter-cap spaces
        let mut buf = Vec::with_capacity(self.encoded_size_hint(caps_len + 1 /* NUL */));
        self.write_first_line_to(&mut buf, capabilities)
            .expect("writing to Vec cannot fail");
        buf.into()
    }

    fn encoded_size_hint(&self, extras: usize) -> usize {
        let hex = self.old_id.kind().len_in_hex();
        // "<hex> SP <hex> SP <refname> LF"
        hex * 2 + 2 + self.refname.len() + 1 + extras
    }
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex fixture")
    }

    const ZERO: &str = "0000000000000000000000000000000000000000";

    #[test]
    fn update_line_has_two_oids_refname_and_lf() {
        let cmd = Command {
            old_id: oid("1111111111111111111111111111111111111111"),
            new_id: oid("2222222222222222222222222222222222222222"),
            refname: "refs/heads/main".into(),
        };
        assert_eq!(
            cmd.to_line(),
            "1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/main\n",
        );
        assert!(cmd.is_update());
        assert!(!cmd.is_create());
        assert!(!cmd.is_delete());
    }

    #[test]
    fn create_is_detected_by_zero_old_id() {
        let cmd = Command {
            old_id: oid(ZERO),
            new_id: oid("000000000000000000000000000000000000000a"),
            refname: "refs/heads/new".into(),
        };
        assert!(cmd.is_create());
        assert!(!cmd.is_delete());
    }

    #[test]
    fn delete_is_detected_by_zero_new_id() {
        let cmd = Command {
            old_id: oid("000000000000000000000000000000000000000a"),
            new_id: oid(ZERO),
            refname: "refs/heads/old".into(),
        };
        assert!(cmd.is_delete());
        assert!(!cmd.is_create());
    }

    #[test]
    fn first_line_appends_nul_and_space_joined_capabilities() {
        let cmd = Command {
            old_id: oid(ZERO),
            new_id: oid("000000000000000000000000000000000000000a"),
            refname: "refs/heads/new".into(),
        };
        let caps = ["report-status", "side-band-64k", "atomic"];
        let line = cmd.to_first_line(&caps);
        assert_eq!(
            line.as_slice(),
            b"0000000000000000000000000000000000000000 000000000000000000000000000000000000000a refs/heads/new\0report-status side-band-64k atomic\n",
        );
    }

    #[test]
    fn first_line_with_empty_capability_list_still_emits_nul_and_lf() {
        let cmd = Command {
            old_id: oid(ZERO),
            new_id: oid("000000000000000000000000000000000000000a"),
            refname: "refs/heads/new".into(),
        };
        let caps: [&str; 0] = [];
        let line = cmd.to_first_line(&caps);
        assert_eq!(
            line.as_slice(),
            b"0000000000000000000000000000000000000000 000000000000000000000000000000000000000a refs/heads/new\0\n",
        );
    }

    #[test]
    fn write_to_appends_into_existing_buffer() {
        let cmd = Command {
            old_id: oid(ZERO),
            new_id: oid("000000000000000000000000000000000000000a"),
            refname: "refs/heads/feature".into(),
        };
        let mut buf = Vec::from(b"PREFIX:".as_ref());
        cmd.write_to(&mut buf).expect("write to Vec cannot fail");
        assert_eq!(
            buf,
            b"PREFIX:0000000000000000000000000000000000000000 000000000000000000000000000000000000000a refs/heads/feature\n",
        );
    }
}
