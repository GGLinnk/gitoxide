//! Pack generation for the client side of `git push`.
//!
//! The pack that goes out in a push contains objects reachable from
//! the local tips being pushed ("wants") but not from the tips the
//! remote already has ("haves"). This module wires together
//! [`gix_traverse::commit::Simple::hide`] for the commit-graph walk,
//! [`gix_pack::data::output::count::objects_for_push`] for the
//! per-commit tree expansion with a have-seeded seen set, and
//! [`gix_pack::data::output::entry::iter_from_counts`] +
//! [`gix_pack::data::output::bytes::FromEntriesIter`] for the
//! streaming byte emitter.
//!
//! The resulting pack is a valid non-thin pack that may include some
//! objects the remote already has but is guaranteed to contain every
//! object reachable from the wants. Optimising the pack further by
//! pre-seeding the already-present set with every blob and sub-tree
//! reachable from the haves is a follow-up; the current shape
//! unblocks real end-to-end pushes.

use std::io::Write;
use std::sync::atomic::AtomicBool;

use gix_hash::ObjectId;
use gix_hashtable::HashSet;

use crate::Repository;

/// Errors produced by [`Repository::write_pack_for_push`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum WritePackError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("commit traversal failed while walking haves")]
    HavesWalk(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("commit traversal failed while walking wants")]
    WantsWalk(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    Count(#[from] gix_pack::data::output::count::objects::Error),
    #[error(transparent)]
    Entries(#[from] gix_pack::data::output::entry::iter_from_counts::Error),
    #[error(transparent)]
    Write(#[from] gix_pack::data::output::bytes::Error<gix_pack::data::output::entry::iter_from_counts::Error>),
}

impl Repository {
    /// Generate a pack containing every object reachable from `wants`
    /// but not from `haves`, and stream the framed pack bytes to
    /// `writer`.
    ///
    /// This is the client-side pack producer used inside a push: the
    /// caller hands the writer provided by
    /// [`gix_protocol::push::Arguments::send`] straight into this
    /// method to get a valid pack on the wire.
    ///
    /// The pack is currently non-thin: all trees and blobs reachable
    /// from commits in `wants \ haves` are included, even if some of
    /// them are identical to objects reachable from the haves. A
    /// follow-up slice will pre-seed the already-present set with the
    /// haves' tree contents to strip those duplicates.
    ///
    /// For delete-only pushes (`wants` is empty), writes nothing and
    /// returns `Ok(())`.
    #[doc(alias = "git pack-objects")]
    pub fn write_pack_for_push<W: Write>(
        &self,
        wants: impl IntoIterator<Item = ObjectId>,
        haves: impl IntoIterator<Item = ObjectId>,
        writer: W,
        should_interrupt: &AtomicBool,
    ) -> Result<(), WritePackError> {
        let wants: Vec<ObjectId> = wants.into_iter().collect();
        let mut haves: Vec<ObjectId> = haves.into_iter().collect();

        if wants.is_empty() {
            return Ok(());
        }

        // Phase 0: drop haves that aren't in our local ODB. Callers
        // often seed haves from every ref the remote advertises in the
        // handshake, and the remote publishes tips that the local
        // client has never fetched (other people's branches, tags on
        // unseen history). Letting an unknown OID reach
        // `commit::Simple::hide(..)` fails the whole walk; filtering
        // here leaves a slightly larger pack than optimal in the worst
        // case but never refuses an otherwise-valid push.
        use gix_object::Exists;
        haves.retain(|oid| self.objects.exists(oid));

        // `haves` bounds the commit walk (via `hide(..)` below); we
        // don't seed `already_present` with haves-reachable commits
        // anymore. A commit-only seed can only help skip commits, not
        // the trees and blobs those commits point at — and if the
        // commit walker fails partway through the haves set, skipping
        // the commits it managed to enumerate while including the
        // ones it didn't leaves the server unable to resolve parent
        // pointers during its connectivity check. Simpler and safer
        // to emit every object reachable from `commits_to_pack` at
        // the cost of a slightly larger pack.
        let already_present: HashSet<ObjectId> = HashSet::default();

        // Phase 2: walk wants' commit graph with haves hidden, so we
        // only see commits that must travel in this push.
        let wants_walker = gix_traverse::commit::Simple::new(wants.iter().copied(), &self.objects)
            .hide(haves.iter().copied())
            .map_err(|e| WritePackError::WantsWalk(Box::new(e) as Box<dyn std::error::Error + Send + Sync>))?;
        let mut commits_to_pack: Vec<ObjectId> = Vec::new();
        for info in wants_walker {
            let info =
                info.map_err(|e| WritePackError::WantsWalk(Box::new(e) as Box<dyn std::error::Error + Send + Sync>))?;
            commits_to_pack.push(info.id);
        }

        if commits_to_pack.is_empty() {
            // No new commits: remote already has everything we wanted
            // to push. Callers generally filter this case out at the
            // refspec layer, but handle it gracefully here too.
            return Ok(());
        }

        // Phase 3: count the objects each commit in scope contributes.
        // `self.objects` is a `Proxy<Cache<Handle<OwnShared<Store>>>>`,
        // where `OwnShared` is `Rc<Store>` without `gix-features/parallel`
        // and `Arc<Store>` with it. `iter_from_counts` below spawns
        // parallel workers and requires `Send + Clone + 'static`, so we
        // must convert to the `Arc<Store>` variant up front via
        // `Cache::into_arc` — which is a no-op when already `Arc`-backed
        // and a clean remap when `Rc`-backed. Without this, the push path
        // fails to compile on `gix` without the `parallel` feature.
        let mut db_clone: gix_odb::Cache<gix_odb::store::Handle<std::sync::Arc<gix_odb::Store>>> =
            (*self.objects).clone().into_arc().map_err(std::io::Error::other)?;
        db_clone.prevent_pack_unload();
        let discard_progress = gix_features::progress::Discard;
        let (counts, _count_outcome): (Vec<gix_pack::data::output::Count>, _) =
            gix_pack::data::output::count::objects_for_push(
                &db_clone,
                commits_to_pack,
                already_present,
                &discard_progress,
                should_interrupt,
            )?;

        if counts.is_empty() {
            return Ok(());
        }
        let num_entries = counts.len() as u32;

        // Phase 4: resolve counts into pack entries (with delta
        // compression decisions made by `iter_from_counts`). The
        // iterator is parallel and needs its own `Find`; clone is
        // cheap because the underlying store is `Arc`-shared.
        let progress =
            Box::new(gix_features::progress::Discard) as Box<dyn gix_features::progress::DynNestedProgress + 'static>;
        let entries_iter = gix_pack::data::output::entry::iter_from_counts(
            counts,
            db_clone,
            progress,
            gix_pack::data::output::entry::iter_from_counts::Options::default(),
        );

        // Phase 5: feed entries through `FromEntriesIter` which writes
        // the pack header, each entry's header+body, and the trailing
        // hash straight into `writer`. Parallel chunk processing inside
        // `iter_from_counts` yields results as they complete, not in
        // submission order; delta entries carry back-references to
        // their base by overall count-index, which is only valid when
        // chunks are emitted in order, so reorder with `InOrderIter`
        // before the pack writer sees the stream. We drive the iterator
        // to completion so the trailer lands and the writer flushes.
        let mapped = gix_features::parallel::InOrderIter::from(entries_iter);
        let bytes_iter = gix_pack::data::output::bytes::FromEntriesIter::new(
            mapped,
            writer,
            num_entries,
            gix_pack::data::Version::V2,
            self.object_hash(),
        );
        for chunk in bytes_iter {
            let _written = chunk?;
        }
        Ok(())
    }
}
