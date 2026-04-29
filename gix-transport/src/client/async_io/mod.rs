//! Async client-side transport primitives.
//!
//! Today this module only exposes enough to talk to a `git://` TCP
//! server via [`connect`]. The blocking counterpart
//! [`super::blocking_io`] additionally ships HTTP transports
//! (reqwest / curl) and an SSH subprocess transport; neither has an
//! async equivalent yet.
//!
//! ## Missing: async HTTP
//!
//! A proper async HTTP transport would:
//! - pick an async HTTP client (hyper, reqwest async, isahc),
//! - implement [`Transport`] including smart-HTTP `info/refs` plus
//!   service-specific POST routing,
//! - thread [`http::Options::extra_headers`](super::blocking_io::http::Options)
//!   parity so bearer-token auth works on both sides,
//! - handle redirects, TLS trust configuration, and streaming
//!   request/response bodies without buffering the whole pack.
//!
//! Deliberately left un-implemented here: it needs an upstream
//! design decision on which async HTTP client to depend on and how
//! the feature flags compose with the blocking HTTP transport's.

mod bufread_ext;
pub use bufread_ext::{ExtendedBufRead, HandleProgress, ReadlineBufRead};

mod request;
pub use request::RequestWriter;

mod traits;
pub use traits::{SetServiceResponse, Transport, TransportV2Ext};

///
pub mod connect;
#[cfg(feature = "async-std")]
pub use connect::function::connect;
