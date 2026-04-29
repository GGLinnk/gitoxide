//! Capability selection and command accumulation for the client side of a
//! push.
//!
//! [`Arguments`] collects [`super::command::Command`] entries to send and
//! negotiates which capabilities to advertise on the first command line,
//! based on the server's handshake-time [`gix_transport::client::Capabilities`]
//! advertisement.
//!
//! The transport integration - writing the pkt-line framed
//! update-request followed by a pack and reading the report-status
//! response - is layered on top of this module by
//! [`Arguments::send`] (blocking) / [`Arguments::send_async`]
//! behind the `blocking-client` / `async-client` features, and by
//! the high-level [`crate::push::response`] module for the response
//! side. The pure-data types in this module remain usable without
//! any transport feature.

use bstr::{BStr, BString};
use gix_transport::client::Capabilities;

use super::command::Command;

/// Well-known capability strings advertised by the server and requested by the
/// client during a push.
///
/// Kept as string constants rather than an enum so that capability handling
/// stays uniform with the rest of the crate, which uses `bstr::BStr` / `&str`
/// against the wire alphabet.
mod cap {
    /// Old-style command-status report.
    pub const REPORT_STATUS: &str = "report-status";
    /// Newer command-status report with `option` annotations. Supersedes `report-status`.
    pub const REPORT_STATUS_V2: &str = "report-status-v2";
    /// Multiplexed response channel capable of larger frames. Supersedes `side-band`.
    pub const SIDE_BAND_64K: &str = "side-band-64k";
    /// Legacy multiplexed response channel with smaller frames.
    pub const SIDE_BAND: &str = "side-band";
    /// All-or-nothing ref-update semantics for the current request.
    pub const ATOMIC: &str = "atomic";
    /// Pack encoding supports offset-delta entries.
    pub const OFS_DELTA: &str = "ofs-delta";
    /// Suppress server-side progress.
    pub const QUIET: &str = "quiet";
    /// Server accepts ref deletions; required to send a zero-new-id command.
    pub const DELETE_REFS: &str = "delete-refs";
    /// Client will send push-options after the pack.
    pub const PUSH_OPTIONS: &str = "push-options";
    /// Agent identification string, sent as `agent=<value>` on the first command line.
    pub const AGENT: &str = "agent";
}

/// Errors raised while configuring [`Arguments`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("server does not advertise the `{capability}` capability")]
    UnsupportedCapability { capability: &'static str },
    #[error("cannot send a deletion for {refname:?} - server does not advertise `delete-refs`")]
    DeletionUnsupported { refname: BString },
}

/// Accumulates ref-update commands and the capability list to advertise on
/// the first command line of a push request.
///
/// The object is constructed from the server's advertised capabilities via
/// [`Arguments::new`], which selects a sensible default subset. The default
/// set always includes `report-status-v2` (or `report-status` if the newer
/// variant is not advertised) and `ofs-delta`, plus `side-band-64k` when
/// available. `atomic`, `quiet`, and `push-options` are opt-in and rejected
/// if the server does not advertise them.
///
/// Ref deletions require the server's `delete-refs` capability; attempting to
/// add a deletion command without that capability returns
/// [`Error::DeletionUnsupported`].
#[derive(Debug, Clone)]
pub struct Arguments {
    commands: Vec<Command>,
    capabilities: Vec<String>,
    server_has_delete_refs: bool,
    server_has_push_options: bool,
    server_has_atomic: bool,
    server_has_quiet: bool,
    server_has_side_band_64k: bool,
    server_has_side_band: bool,
    /// Raw push-options that will be sent after the pack when
    /// `push-options` is on the capability list. `None` means: do not send a
    /// push-options trailer; `Some(vec![])` means: send an empty trailer.
    push_options: Option<Vec<BString>>,
}

impl Arguments {
    /// Create a new command accumulator from the server's handshake
    /// advertisement.
    ///
    /// The default capability set is computed eagerly and is observable via
    /// the `can_use_*` query methods. It can be inspected or replaced with
    /// [`Arguments::capabilities_mut`] for callers that need precise control.
    pub fn new(server: &Capabilities) -> Self {
        let has = |name: &str| server.contains(name);
        let has_report_status = has(cap::REPORT_STATUS);
        let has_report_status_v2 = has(cap::REPORT_STATUS_V2);
        let server_has_side_band_64k = has(cap::SIDE_BAND_64K);
        let server_has_side_band = has(cap::SIDE_BAND);
        let server_has_atomic = has(cap::ATOMIC);
        let server_has_delete_refs = has(cap::DELETE_REFS);
        let server_has_push_options = has(cap::PUSH_OPTIONS);
        let server_has_quiet = has(cap::QUIET);
        let server_has_ofs_delta = has(cap::OFS_DELTA);

        let mut capabilities = Vec::with_capacity(4);
        if has_report_status_v2 {
            capabilities.push(cap::REPORT_STATUS_V2.to_owned());
        } else if has_report_status {
            capabilities.push(cap::REPORT_STATUS.to_owned());
        }
        if server_has_side_band_64k {
            capabilities.push(cap::SIDE_BAND_64K.to_owned());
        } else if server_has_side_band {
            capabilities.push(cap::SIDE_BAND.to_owned());
        }
        if server_has_ofs_delta {
            capabilities.push(cap::OFS_DELTA.to_owned());
        }

        Self {
            commands: Vec::new(),
            capabilities,
            server_has_delete_refs,
            server_has_push_options,
            server_has_atomic,
            server_has_quiet,
            server_has_side_band_64k,
            server_has_side_band,
            push_options: None,
        }
    }

    /// Set the `agent=<value>` capability on the advertisement.
    ///
    /// Replaces any previous agent value. `agent` has no gating capability on
    /// the server side, so this never fails.
    pub fn set_agent(&mut self, agent: &str) {
        self.capabilities
            .retain(|c| !c.starts_with(&format!("{}=", cap::AGENT)));
        self.capabilities.push(format!("{}={agent}", cap::AGENT));
    }

    /// Set the `object-format=<name>` capability on the first command
    /// line. git-send-pack emits this from 2.28 onwards whenever the
    /// server advertised `object-format` so both sides agree on the
    /// repository's hash algorithm. Replaces any previous value.
    ///
    /// Accept any byte string so SHA-1 / SHA-256 remain the caller's
    /// responsibility.
    pub fn set_object_format(&mut self, name: &str) {
        let prefix = "object-format=";
        self.capabilities.retain(|c| !c.starts_with(prefix));
        self.capabilities.push(format!("{prefix}{name}"));
    }

    /// Enable the `atomic` capability, requesting all-or-nothing application
    /// of the commands.
    ///
    /// Fails with [`Error::UnsupportedCapability`] if the server did not
    /// advertise `atomic`.
    pub fn use_atomic(&mut self) -> Result<(), Error> {
        if !self.server_has_atomic {
            return Err(Error::UnsupportedCapability {
                capability: cap::ATOMIC,
            });
        }
        if !self.capabilities.iter().any(|c| c == cap::ATOMIC) {
            self.capabilities.push(cap::ATOMIC.to_owned());
        }
        Ok(())
    }

    /// Enable the `quiet` capability, asking the server to suppress progress.
    ///
    /// Per `gitprotocol-capabilities`, `quiet` is advertised by the
    /// server like every other push capability; a client that selects
    /// it without a matching advertisement is sending an unknown
    /// token. Fails with [`Error::UnsupportedCapability`] when the
    /// server did not advertise `quiet`.
    pub fn use_quiet(&mut self) -> Result<(), Error> {
        if !self.server_has_quiet {
            return Err(Error::UnsupportedCapability {
                capability: cap::QUIET,
            });
        }
        if !self.capabilities.iter().any(|c| c == cap::QUIET) {
            self.capabilities.push(cap::QUIET.to_owned());
        }
        Ok(())
    }

    /// Register push-options to be sent after the pack, and advertise the
    /// `push-options` capability.
    ///
    /// Passing an empty `options` vector still advertises the capability and
    /// will cause the transport layer to emit a single flush-pkt as the
    /// push-options trailer (per spec).
    ///
    /// Fails with [`Error::UnsupportedCapability`] if the server did not
    /// advertise `push-options`.
    pub fn use_push_options(&mut self, options: Vec<BString>) -> Result<(), Error> {
        if !self.server_has_push_options {
            return Err(Error::UnsupportedCapability {
                capability: cap::PUSH_OPTIONS,
            });
        }
        if !self.capabilities.iter().any(|c| c == cap::PUSH_OPTIONS) {
            self.capabilities.push(cap::PUSH_OPTIONS.to_owned());
        }
        self.push_options = Some(options);
        Ok(())
    }

    /// Append a ref-update command.
    ///
    /// Rejects deletions (zero `new_id`) if the server did not advertise
    /// `delete-refs`.
    pub fn add_command(&mut self, command: Command) -> Result<(), Error> {
        if command.is_delete() && !self.server_has_delete_refs {
            return Err(Error::DeletionUnsupported {
                refname: command.refname.clone(),
            });
        }
        self.commands.push(command);
        Ok(())
    }

    /// Returns the accumulated commands in send order.
    pub fn commands(&self) -> &[Command] {
        &self.commands
    }

    /// Returns the capability list as it will appear on the first command
    /// line, in order.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Allow callers to fine-tune the capability advertisement, e.g. to
    /// remove a default that is undesired for a given transport.
    ///
    /// No validation is performed against the server advertisement; callers
    /// that use this escape hatch are responsible for staying within the
    /// server's declared support.
    pub fn capabilities_mut(&mut self) -> &mut Vec<String> {
        &mut self.capabilities
    }

    /// Returns the push-options that will be sent after the pack, if any.
    ///
    /// Only meaningful when the `push-options` capability has been enabled
    /// via [`Self::use_push_options`].
    pub fn push_options(&self) -> Option<&[BString]> {
        self.push_options.as_deref()
    }

    /// Returns `true` if no commands have been added.
    ///
    /// An empty [`Arguments`] is invalid to send; callers should treat this
    /// as a no-op push.
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Returns `true` if `atomic` was advertised by the server.
    pub fn can_use_atomic(&self) -> bool {
        self.server_has_atomic
    }

    /// Returns `true` if `quiet` was advertised by the server.
    pub fn can_use_quiet(&self) -> bool {
        self.server_has_quiet
    }

    /// Returns `true` if `push-options` was advertised by the server.
    pub fn can_use_push_options(&self) -> bool {
        self.server_has_push_options
    }

    /// Returns `true` if either side-band variant was advertised.
    pub fn can_use_side_band(&self) -> bool {
        self.server_has_side_band_64k || self.server_has_side_band
    }

    /// Returns `true` if the server will accept deletion commands.
    pub fn can_delete_refs(&self) -> bool {
        self.server_has_delete_refs
    }

    /// Returns `true` if the advertised capability set currently includes
    /// `report-status-v2`.
    ///
    /// The response parser selection follows this: `true` means parse with
    /// [`super::report_status::parse_report_v2`], otherwise with
    /// [`super::report_status::parse_report_v1`].
    pub fn expects_report_status_v2(&self) -> bool {
        self.capabilities.iter().any(|c| c == cap::REPORT_STATUS_V2)
    }

    /// Serialize the full update-request block into a sequence of
    /// LF-terminated pkt-line payloads.
    ///
    /// The first command line carries the capability list after a NUL byte.
    /// Subsequent command lines carry only the ref-update. A trailing
    /// flush-pkt is NOT included - the transport layer emits it separately
    /// before the pack bytes.
    ///
    /// Returns an empty vector when [`Self::is_empty`] is `true`.
    pub fn emit_command_lines(&self) -> Vec<BString> {
        if self.commands.is_empty() {
            return Vec::new();
        }
        let mut lines = Vec::with_capacity(self.commands.len());
        let (first, rest) = self.commands.split_first().expect("non-empty");
        lines.push(first.to_first_line(&self.capabilities));
        for cmd in rest {
            lines.push(cmd.to_line());
        }
        lines
    }
}

/// Check whether the server advertises an `agent` capability, returning its
/// value if so.
///
/// Convenience for callers that want to record the server agent alongside
/// their own.
pub fn server_agent(server: &Capabilities) -> Option<&BStr> {
    server.capability(cap::AGENT).and_then(|c| c.value())
}

/// Errors raised while sending an update-request over a transport.
#[cfg(any(feature = "blocking-client", feature = "async-client"))]
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum SendError {
    #[error("no commands to send - `Arguments::add_command` was never called with a valid entry")]
    Empty,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Transport(#[from] gix_transport::client::Error),
}

#[cfg(any(feature = "blocking-client", feature = "async-client"))]
impl gix_transport::IsSpuriousError for SendError {
    fn is_spurious(&self) -> bool {
        match self {
            SendError::Io(err) => err.is_spurious(),
            SendError::Transport(err) => err.is_spurious(),
            SendError::Empty => false,
        }
    }
}

#[cfg(feature = "async-client")]
mod async_io {
    use futures_lite::io::{AsyncWrite, AsyncWriteExt as _};
    use gix_transport::client::{
        async_io::{ExtendedBufRead, Transport},
        MessageKind, WriteMode,
    };

    use super::{Arguments, SendError};

    impl Arguments {
        /// Async counterpart of the blocking [`Arguments::send`].
        ///
        /// `write_pack` is an async closure that receives the raw transport
        /// writer and returns a future resolving to `io::Result<()>`. It is
        /// responsible for emitting a complete git pack; delete-only pushes
        /// may return `Ok(())` without writing anything.
        pub async fn send<'a, T, W, F>(
            &mut self,
            transport: &'a mut T,
            write_pack: W,
            trace: bool,
        ) -> Result<Box<dyn ExtendedBufRead<'a> + Unpin + 'a>, SendError>
        where
            T: Transport + 'a,
            W: FnOnce(Box<dyn AsyncWrite + Unpin + 'a>) -> F,
            F: std::future::Future<Output = std::io::Result<Box<dyn AsyncWrite + Unpin + 'a>>>,
        {
            if self.commands.is_empty() {
                return Err(SendError::Empty);
            }

            let mut writer =
                transport.request(WriteMode::OneLfTerminatedLinePerWriteCall, MessageKind::Flush, trace)?;

            for line in self.emit_command_lines() {
                writer.write_all(&line).await?;
            }
            writer.write_message(MessageKind::Flush).await?;

            if let Some(options) = self.push_options.as_deref() {
                for opt in options {
                    writer.write_all(opt).await?;
                }
                writer.write_message(MessageKind::Flush).await?;
            }

            let (raw_writer, reader) = writer.into_parts();
            let mut raw_writer = write_pack(raw_writer).await?;
            raw_writer.flush().await?;
            Ok(reader)
        }
    }
}

#[cfg(feature = "blocking-client")]
mod blocking_io {
    use std::io::Write as _;

    use gix_transport::client::{
        blocking_io::{ExtendedBufRead, Transport},
        MessageKind, WriteMode,
    };

    use super::{Arguments, SendError};

    impl Arguments {
        /// Send the accumulated update-request over `transport`, stream the
        /// pack through `write_pack`, and return a reader positioned at the
        /// start of the server's response.
        ///
        /// The emitted byte sequence follows the pack-protocol
        /// update-request grammar:
        ///
        /// 1. The first command line with the NUL-separated capability list.
        /// 2. Any additional command lines, one per pkt-line.
        /// 3. A flush-pkt terminating the command-list.
        /// 4. If `push-options` was enabled via [`Self::use_push_options`]:
        ///    each option as its own pkt-line, followed by a flush-pkt.
        /// 5. The raw pack bytes, written by `write_pack`.
        ///
        /// `write_pack` receives a writer into the underlying transport
        /// stream with pkt-line framing *disabled*; it is responsible for
        /// emitting a complete git pack. Delete-only pushes may pass a
        /// no-op closure that writes nothing, per the pack-protocol rule
        /// that the pack-file is optional when no commands require it.
        ///
        /// The returned reader is the server's response stream and is ready
        /// for pkt-line consumption. Side-band demultiplexing, when
        /// negotiated, is the caller's responsibility; see
        /// [`Self::expects_report_status_v2`] and [`Self::can_use_side_band`]
        /// to decide how to parse the response.
        ///
        /// `trace` enables the `gix-trace` hooks on every written and read
        /// pkt-line, matching the convention of [`crate::fetch::Arguments::send`].
        pub fn send<'a, T, W>(
            &mut self,
            transport: &'a mut T,
            write_pack: W,
            trace: bool,
        ) -> Result<Box<dyn ExtendedBufRead<'a> + Unpin + 'a>, SendError>
        where
            T: Transport + 'a,
            W: FnOnce(&mut (dyn std::io::Write + '_)) -> std::io::Result<()>,
        {
            if self.commands.is_empty() {
                return Err(SendError::Empty);
            }

            let mut writer =
                transport.request(WriteMode::OneLfTerminatedLinePerWriteCall, MessageKind::Flush, trace)?;

            for line in self.emit_command_lines() {
                writer.write_all(&line)?;
            }
            writer.write_message(MessageKind::Flush)?;

            if let Some(options) = self.push_options.as_deref() {
                for opt in options {
                    writer.write_all(opt)?;
                }
                writer.write_message(MessageKind::Flush)?;
            }

            let (mut raw_writer, reader) = writer.into_parts();
            write_pack(&mut raw_writer)?;
            raw_writer.flush()?;
            Ok(reader)
        }
    }
}

#[cfg(all(test, feature = "sha1"))]
mod tests {
    use super::*;

    fn caps(bytes: &'static [u8]) -> Capabilities {
        Capabilities::from_bytes(bytes).expect("valid capability bytes").0
    }

    fn oid(hex: &str) -> gix_hash::ObjectId {
        gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("valid hex")
    }

    fn any_delete() -> Command {
        Command {
            old_id: oid("1111111111111111111111111111111111111111"),
            new_id: oid("0000000000000000000000000000000000000000"),
            refname: "refs/heads/old".into(),
        }
    }

    #[test]
    fn defaults_prefer_v2_and_side_band_64k() {
        let server = caps(b"\0report-status report-status-v2 side-band side-band-64k ofs-delta delete-refs atomic");
        let args = Arguments::new(&server);
        assert_eq!(
            args.capabilities(),
            &[
                "report-status-v2".to_owned(),
                "side-band-64k".to_owned(),
                "ofs-delta".to_owned(),
            ],
        );
    }

    #[test]
    fn defaults_fall_back_to_old_report_status_and_side_band() {
        let server = caps(b"\0report-status side-band ofs-delta");
        let args = Arguments::new(&server);
        assert_eq!(
            args.capabilities(),
            &[
                "report-status".to_owned(),
                "side-band".to_owned(),
                "ofs-delta".to_owned(),
            ],
        );
    }

    #[test]
    fn set_object_format_adds_and_replaces_the_capability() {
        let server = caps(b"\0report-status object-format=sha1");
        let mut args = Arguments::new(&server);
        args.set_object_format("sha1");
        assert_eq!(
            args.capabilities()
                .iter()
                .filter(|c| c.starts_with("object-format="))
                .count(),
            1
        );
        assert!(args.capabilities().iter().any(|c| c == "object-format=sha1"));
        // Replace with a new value; the old one must be dropped.
        args.set_object_format("sha256");
        assert_eq!(
            args.capabilities()
                .iter()
                .filter(|c| c.starts_with("object-format="))
                .count(),
            1
        );
        assert!(args.capabilities().iter().any(|c| c == "object-format=sha256"));
    }

    #[test]
    fn atomic_is_rejected_when_server_omits_it() {
        let server = caps(b"\0report-status");
        let mut args = Arguments::new(&server);
        match args.use_atomic() {
            Err(Error::UnsupportedCapability { capability }) => assert_eq!(capability, "atomic"),
            other => panic!("expected UnsupportedCapability, got {other:?}"),
        }
    }

    #[test]
    fn atomic_is_added_when_advertised_and_is_idempotent() {
        let server = caps(b"\0report-status atomic");
        let mut args = Arguments::new(&server);
        args.use_atomic().expect("atomic is advertised");
        args.use_atomic().expect("idempotent");
        let count = args.capabilities().iter().filter(|c| *c == "atomic").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn quiet_is_rejected_when_server_omits_it() {
        let server = caps(b"\0report-status");
        let mut args = Arguments::new(&server);
        assert!(!args.can_use_quiet());
        match args.use_quiet() {
            Err(Error::UnsupportedCapability { capability }) => assert_eq!(capability, "quiet"),
            other => panic!("expected UnsupportedCapability, got {other:?}"),
        }
    }

    #[test]
    fn quiet_is_added_when_advertised_and_is_idempotent() {
        let server = caps(b"\0report-status quiet");
        let mut args = Arguments::new(&server);
        assert!(args.can_use_quiet());
        args.use_quiet().expect("quiet is advertised");
        args.use_quiet().expect("idempotent");
        let count = args.capabilities().iter().filter(|c| *c == "quiet").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn push_options_requires_advertisement_and_records_values() {
        let server_without = caps(b"\0report-status");
        let mut args = Arguments::new(&server_without);
        assert!(args.use_push_options(vec!["key=value".into()]).is_err());

        let server_with = caps(b"\0report-status push-options");
        let mut args = Arguments::new(&server_with);
        args.use_push_options(vec!["key=value".into()]).unwrap();
        assert!(args.capabilities().iter().any(|c| c == "push-options"));
        assert_eq!(args.push_options(), Some(&[BString::from("key=value")][..]));
    }

    #[test]
    fn deletions_require_delete_refs_capability() {
        let server = caps(b"\0report-status");
        let mut args = Arguments::new(&server);
        match args.add_command(any_delete()) {
            Err(Error::DeletionUnsupported { refname }) => {
                assert_eq!(refname, "refs/heads/old");
            }
            other => panic!("expected DeletionUnsupported, got {other:?}"),
        }
        assert!(args.commands().is_empty());
    }

    #[test]
    fn deletions_are_accepted_when_delete_refs_is_advertised() {
        let server = caps(b"\0report-status delete-refs");
        let mut args = Arguments::new(&server);
        args.add_command(any_delete()).expect("delete-refs is advertised");
        assert_eq!(args.commands().len(), 1);
    }

    #[test]
    fn emit_command_lines_attaches_caps_only_to_first() {
        let server = caps(b"\0report-status ofs-delta");
        let mut args = Arguments::new(&server);
        args.add_command(Command {
            old_id: oid("1111111111111111111111111111111111111111"),
            new_id: oid("2222222222222222222222222222222222222222"),
            refname: "refs/heads/main".into(),
        })
        .unwrap();
        args.add_command(Command {
            old_id: oid("3333333333333333333333333333333333333333"),
            new_id: oid("4444444444444444444444444444444444444444"),
            refname: "refs/heads/feature".into(),
        })
        .unwrap();

        let lines = args.emit_command_lines();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains(&0), "first line must contain NUL");
        assert!(lines[0].windows(13).any(|w| w == b"report-status"));
        assert!(!lines[1].contains(&0), "subsequent lines must not contain NUL");
    }

    #[test]
    fn emit_command_lines_is_empty_when_no_commands_added() {
        let server = caps(b"\0report-status");
        let args = Arguments::new(&server);
        assert!(args.emit_command_lines().is_empty());
        assert!(args.is_empty());
    }

    #[test]
    fn expects_report_status_v2_is_true_only_when_v2_selected() {
        let server_v2 = caps(b"\0report-status-v2");
        assert!(Arguments::new(&server_v2).expects_report_status_v2());

        let server_v1 = caps(b"\0report-status");
        assert!(!Arguments::new(&server_v1).expects_report_status_v2());
    }

    #[test]
    fn set_agent_appends_and_replaces() {
        let server = caps(b"\0report-status");
        let mut args = Arguments::new(&server);
        args.set_agent("gix/1.0");
        assert!(args.capabilities().iter().any(|c| c == "agent=gix/1.0"));
        args.set_agent("gix/2.0");
        let agents: Vec<_> = args.capabilities().iter().filter(|c| c.starts_with("agent=")).collect();
        assert_eq!(agents, vec![&"agent=gix/2.0".to_owned()]);
    }
}
