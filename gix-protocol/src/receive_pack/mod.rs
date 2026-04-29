//! Server-side implementation of `git-receive-pack`, the service that
//! answers `git push` requests.
//!
//! This is the server counterpart to [`crate::push`]: where `push` emits
//! command lines and parses the `report-status` response, `receive_pack`
//! parses command lines (server-side) and emits the `report-status` /
//! `report-status-v2` response.
//!
//! ## Module layout
//!
//! - [`advertisement`] - emit the ref / capability advertisement
//!   (`info/refs?service=git-receive-pack`).
//! - [`commands`] - parse the client's update-request command block
//!   into [`ParsedRequest`] (ref updates + requested capabilities).
//! - [`report`] - emit a `report-status` or `report-status-v2` response
//!   as ordered pkt-line payloads.
//! - [`serve`] - the end-to-end state machine:
//!   [`serve_blocking`] / [`serve_with_hooks`] read commands, drain
//!   the optional push-options section, run caller-supplied hooks,
//!   invoke the caller's pack ingester, apply ref updates via the
//!   caller's `apply_updates` closure, and emit the report. V2
//!   report-status-v2 is auto-selected when the client advertises it.
//! - [`serve_info_refs`] - pkt-line framing for the `info/refs`
//!   banner.
//!
//! ## Naming note
//!
//! `gix-protocol`'s client side has a small module named
//! `gix/src/remote/connection/fetch/receive_pack.rs` - that one handles
//! the *client-side* reception of a pack during fetch. This module
//! (`gix-protocol::receive_pack`) is the *server-side* handler for the
//! `git-receive-pack` service. Keep the distinction explicit in any docs
//! that reference either.

pub mod advertisement;
pub mod commands;
pub mod report;
pub mod serve;
pub mod serve_info_refs;

pub use advertisement::{AdvertisedRef, Options};
pub use commands::{ParsedRequest, RequestedCapabilities};
pub use report::emit_v1;
pub use report::emit_v2;
pub use serve::{
    serve as serve_blocking, serve_with_hooks, serve_with_options_and_hooks, ServeError, ServeHooks, ServeOptions,
    ServeOutcome, UpdateOutcome,
};

/// Re-export the push command type so server-side callers do not need to
/// pull in the `push` module path separately. Both sides model the same
/// wire object.
pub use crate::push::Command;
