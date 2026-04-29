//! In-process transports that bridge `gix_transport::client::Transport`
//! to a same-process server loop running against a local
//! [`Repository`](crate::Repository).
//!
//! Downstream callers that today shell out to `git-receive-pack` or
//! `git-upload-pack` can instead wire `Remote::push` or fetch through
//! one of these helpers and talk to an in-process server through a
//! pair of byte channels. No sockets, no subprocess, no network.
//!
//! The server runs on a detached worker thread and owns a
//! [`ThreadSafeRepository`](crate::ThreadSafeRepository) clone for the
//! duration of the exchange. When the exchange finishes the thread
//! returns; dropping the client-side transport closes the channels
//! and lets the worker exit cleanly even mid-exchange (the server
//! function sees EOF).
//!
//! Because the worker thread takes ownership of a `ThreadSafeRepository`,
//! the `parallel` feature (bundled in the default feature set) is
//! required for `Send` propagation.

#[cfg(feature = "serve-receive-pack")]
use gix_protocol::receive_pack;
use gix_transport::{
    client::{
        blocking_io::in_process::{ChannelReader, ChannelWriter},
        git,
    },
    Protocol,
};

type Channel<R, W> = git::blocking_io::Connection<R, W>;

impl crate::Repository {
    /// Return a [`Transport`](gix_transport::client::blocking_io::Transport)
    /// that speaks `git-receive-pack` v0/v1 against an in-process
    /// server running on a worker thread against a snapshot of this
    /// repository.
    ///
    /// The server thread emits the v1 ref advertisement
    /// (via [`Self::serve_receive_pack_info_refs`]), then drives
    /// [`Self::serve_pack_receive`] against the client's
    /// update-request + pack, then emits the `report-status` (or
    /// `report-status-v2` when the client negotiated it) response and
    /// exits.
    ///
    /// Typical usage is wiring the returned transport into
    /// [`Remote::to_connection_with_transport`](crate::remote::Remote::to_connection_with_transport)
    /// and driving a full push through `prepare_push` / `send` without
    /// shelling out.
    #[cfg(all(
        feature = "serve-receive-pack",
        feature = "blocking-network-client",
        feature = "parallel"
    ))]
    pub fn in_process_receive_pack_transport(&self) -> Channel<ChannelReader, ChannelWriter> {
        let repo_sync = self.clone().into_sync();
        let hash_name = object_hash_wire_name(self.object_hash());
        let (client_reader, client_writer) =
            gix_transport::client::blocking_io::in_process::spawn_server(move |reader, mut writer| {
                let repo = repo_sync.to_thread_local();
                // Side-band framing buys nothing in-process and
                // `serve_pack_receive` emits a bare report, so disable
                // both side-band advertisements to keep the response
                // shape in lockstep with the client's parser.
                let options = receive_pack::Options {
                    side_band_64k: false,
                    side_band: false,
                    object_format: Some(crate::bstr::BString::from(hash_name.as_str())),
                    ..receive_pack::Options::default()
                };
                repo.serve_receive_pack_info_refs(&mut writer, &options)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                let should_interrupt = std::sync::atomic::AtomicBool::new(false);
                let mut progress = gix_features::progress::Discard;
                let _outcome = repo
                    .serve_pack_receive(reader, &mut writer, &mut progress, &should_interrupt)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                Ok(())
            });
        Channel::new(
            client_reader,
            client_writer,
            Protocol::V1,
            "in-process",
            None::<(&str, _)>,
            git::ConnectMode::Process,
            false,
        )
    }

    /// Return a [`Transport`](gix_transport::client::blocking_io::Transport)
    /// that speaks `git-upload-pack` v0/v1 against an in-process
    /// server running on a worker thread against a snapshot of this
    /// repository.
    ///
    /// The server emits the v1 ref advertisement with upload-side
    /// capabilities then drives [`Self::serve_pack_upload_v1_auto`]
    /// against the client's upload-request and streams the resulting
    /// pack. Useful for fetching from a local repo without a
    /// subprocess.
    #[cfg(all(
        feature = "serve-upload-pack",
        feature = "blocking-network-client",
        feature = "parallel"
    ))]
    pub fn in_process_upload_pack_transport_v1(&self) -> Channel<ChannelReader, ChannelWriter> {
        let repo_sync = self.clone().into_sync();
        let hash_name = object_hash_wire_name(self.object_hash());
        let (client_reader, client_writer) =
            gix_transport::client::blocking_io::in_process::spawn_server(move |reader, mut writer| {
                let repo = repo_sync.to_thread_local();
                let options = gix_protocol::upload_pack::Options {
                    object_format: Some(gix_protocol::transport::bstr::BString::from(hash_name.as_str())),
                    ..gix_protocol::upload_pack::Options::default()
                };
                repo.serve_upload_pack_info_refs(&mut writer, &options)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                let should_interrupt = std::sync::atomic::AtomicBool::new(false);
                let _outcome = repo
                    .serve_pack_upload_v1_auto(reader, &mut writer, &should_interrupt)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                Ok(())
            });
        Channel::new(
            client_reader,
            client_writer,
            Protocol::V1,
            "in-process",
            None::<(&str, _)>,
            git::ConnectMode::Process,
            false,
        )
    }

    /// Return a [`Transport`](gix_transport::client::blocking_io::Transport)
    /// that speaks `git-upload-pack` v2 against an in-process server
    /// running on a worker thread against a snapshot of this
    /// repository.
    ///
    /// The server emits the v2 advertisement (capabilities only; no
    /// refs) then drives [`Self::serve_pack_upload_v2_dispatch_auto`]
    /// to answer one or more commands (`command=ls-refs` followed by
    /// `command=fetch`).
    #[cfg(all(
        feature = "serve-upload-pack",
        feature = "blocking-network-client",
        feature = "parallel"
    ))]
    pub fn in_process_upload_pack_transport_v2(&self) -> Channel<ChannelReader, ChannelWriter> {
        let repo_sync = self.clone().into_sync();
        let hash_name = object_hash_wire_name(self.object_hash());
        let (client_reader, client_writer) =
            gix_transport::client::blocking_io::in_process::spawn_server(move |reader, mut writer| {
                let repo = repo_sync.to_thread_local();
                let options = gix_protocol::upload_pack::OptionsV2 {
                    object_format: Some(gix_protocol::transport::bstr::BString::from(hash_name.as_str())),
                    ..gix_protocol::upload_pack::OptionsV2::default()
                };
                repo.serve_upload_pack_info_refs_v2(&mut writer, &options)?;
                let should_interrupt = std::sync::atomic::AtomicBool::new(false);
                let _outcome = repo
                    .serve_pack_upload_v2_dispatch_auto(reader, &mut writer, &should_interrupt)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                Ok(())
            });
        Channel::new(
            client_reader,
            client_writer,
            Protocol::V2,
            "in-process",
            None::<(&str, _)>,
            git::ConnectMode::Process,
            false,
        )
    }
}

/// Wire-level `object-format=<name>` value for the given hash kind.
///
/// `gix-hash::Kind` is non-exhaustive so a `match` would risk a
/// compile error when new kinds land upstream; a name-based lookup
/// stays forward-compatible by routing any unfamiliar kind through
/// its `to_string` representation.
#[cfg(any(feature = "serve-receive-pack", feature = "serve-upload-pack"))]
fn object_hash_wire_name(kind: gix_hash::Kind) -> String {
    kind.to_string()
}
