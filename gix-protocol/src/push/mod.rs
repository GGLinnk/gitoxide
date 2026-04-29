//! Wire-types and orchestration for the client side of `git push`.
//!
//! This module covers the full client-side push surface defined by the
//! [pack protocol][spec-v1] and [protocol v2][spec-v2]: command
//! serialisation, capability negotiation, pack streaming, and
//! `report-status` / `report-status-v2` parsing.
//!
//! ## Module layout
//!
//! - [`command::Command`] - a single ref-update instruction, serialisable
//!   as a pkt-line payload via [`command::Command::write_to`] /
//!   [`command::Command::write_first_line_to`].
//! - [`arguments::Arguments`] - capability selection and command
//!   accumulation. [`arguments::Arguments::send`] (blocking) /
//!   [`arguments::Arguments::send_async`] (async) frame the command list
//!   + flush + optional push-options and delegate pack generation to a
//!   caller closure.
//! - [`report_status`] - typed parsers for `report-status` (v1) and
//!   `report-status-v2`, plus the shared `CommandOptions` trailer type.
//! - [`response`] - side-band demux + high-level [`response::Outcome`]
//!   with success-inspection helpers (`is_success`, `accepted_count`,
//!   `rejected_count`, `command_statuses()`).
//!
//! [spec-v1]: https://git-scm.com/docs/pack-protocol#_reference_update_request_and_packfile_transfer
//! [spec-v2]: https://git-scm.com/docs/protocol-v2#_push

pub mod arguments;
pub mod command;
pub mod report_status;
#[cfg(any(feature = "blocking-client", feature = "async-client"))]
pub mod response;

pub use arguments::Arguments;
pub use command::Command;
pub use report_status::{CommandOptions, CommandStatus, CommandStatusV2, Report, ReportV2, UnpackStatus};
#[cfg(any(feature = "blocking-client", feature = "async-client"))]
pub use response::{Outcome as PushOutcome, ReportKind, SideBandMode};
