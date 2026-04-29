//! Pack-counting for the push (send-pack) side.
//!
//! Clones and fetches compute their object set via [`super::objects`]
//! with an [`super::ObjectExpansion`] variant. Push has different
//! semantics: the set of objects to send is "reachable from the
//! wanted tips, minus anything the remote already has".
//!
//! The commit-graph walk with boundary exclusion lives in
//! `gix_traverse::commit::Simple::hide` (already implemented); this
//! module handles the pack-counting step that follows. The caller
//! walks the commit graph, collects the commits that should ship in
//! the pack, and also builds a set of objects already present on the
//! remote (typically by walking the trees of the `have` tips). Those
//! two inputs feed [`objects_for_push`], which emits one
//! [`super::super::Count`] per object that should travel.
//!
//! A purely caller-side API keeps `gix-pack` decoupled from the
//! commit walker and the ref store while still allowing reuse of the
//! breadth-first tree traversal and object-db access logic that
//! [`super::objects`] already carries.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};

use gix_hash::{oid, ObjectId};
use gix_hashtable::HashSet;
use gix_object::{CommitRefIter, Data, TagRefIter};

use crate::data::output;
use crate::data::output::count::objects::{Error, Outcome};
use crate::FindExt;

/// Filter applied during push-side object counting to support the
/// partial-clone semantics a `git upload-pack` client can request via
/// `filter=<spec>`.
///
/// The upload-pack server honours this filter by skipping the filtered
/// object kinds before they reach the pack-entry generator. The
/// resulting pack is a partial pack that the client must later
/// back-fill with a follow-up promisor fetch.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFilter {
    /// No filtering — every reachable commit, tree, blob, and tag
    /// becomes a pack entry. This is the default behaviour equivalent
    /// to calling [`objects_for_push`] directly.
    #[default]
    None,
    /// Skip every blob. Matches the `filter=blob:none` wire directive:
    /// commits, trees, and annotated tags still ship, so the client
    /// can verify the history, but file contents are omitted.
    BlobsNone,
    /// Skip every blob whose decoded size in bytes is at least the
    /// limit. Matches the `filter=blob:limit=<n>` wire directive: small
    /// files survive the filter so the client can still diff and build
    /// the tree, while large binary payloads are deferred to a
    /// promisor back-fill.
    BlobsAtLeast(u64),
    /// Skip every tree (and by extension every blob, since blobs are
    /// only reached through tree traversal). Commits, annotated tags,
    /// and tag chains still ship. Matches git's `filter=tree:0`
    /// directive, which is equivalent to `object:type=commit` for
    /// repositories without annotated tag chains - a history-only
    /// clone the client back-fills on demand.
    TreesNone,
}

/// Count the objects that would make up a pack sent in response to
/// `commits_to_pack`, skipping anything the remote already has.
///
/// - `db` accesses the local object store.
/// - `commits_to_pack` are the commits that must ship. Callers typically
///   populate this from `gix_traverse::commit::Simple::new(wants)
///   .hide(haves)`, but any order-preserving iterator of commit OIDs
///   works. Tag targets are followed transparently; blob or tree OIDs
///   passed directly are emitted as-is.
/// - `already_present` is the set of object IDs known to exist on the
///   remote. It MUST include every tree and blob reachable from the
///   haves the remote advertised; the simplest way to populate it is
///   to walk each have's tree recursively before calling this function.
///   The set is extended internally with newly-emitted OIDs so repeat
///   calls don't ship the same object twice.
/// - `progress` is incremented per emitted count.
/// - `should_interrupt` is polled between commits and between trees.
///
/// Returns the ordered list of [`output::Count`] entries ready to be
/// fed into the pack-entry generator, plus the aggregate
/// [`Outcome`] statistics.
#[doc(alias = "git pack-objects")]
pub fn objects_for_push<Find>(
    db: &Find,
    commits_to_pack: impl IntoIterator<Item = ObjectId>,
    already_present: HashSet<ObjectId>,
    progress: &dyn gix_features::progress::Count,
    should_interrupt: &AtomicBool,
) -> Result<(Vec<output::Count>, Outcome), Error>
where
    Find: crate::Find,
{
    objects_for_push_with_filter(
        db,
        commits_to_pack,
        already_present,
        ObjectFilter::None,
        progress,
        should_interrupt,
    )
}

/// Variant of [`objects_for_push`] that honours a partial-clone
/// [`ObjectFilter`].
///
/// Use this when a `git upload-pack` client negotiated a
/// `filter=<spec>` capability: the returned [`output::Count`] list
/// skips every object kind the filter excludes. `objects_for_push` is
/// equivalent to calling this function with [`ObjectFilter::None`].
#[doc(alias = "git pack-objects")]
pub fn objects_for_push_with_filter<Find>(
    db: &Find,
    commits_to_pack: impl IntoIterator<Item = ObjectId>,
    already_present: HashSet<ObjectId>,
    filter: ObjectFilter,
    progress: &dyn gix_features::progress::Count,
    should_interrupt: &AtomicBool,
) -> Result<(Vec<output::Count>, Outcome), Error>
where
    Find: crate::Find,
{
    let mut out = Vec::new();
    let mut outcome = Outcome::default();
    let objects_counter = progress.counter();

    let seen: RefCell<HashSet<ObjectId>> = RefCell::new(already_present);
    let mut buf1 = Vec::new();
    let mut buf2 = Vec::new();
    let mut tree_state = gix_traverse::tree::breadthfirst::State::default();

    for commit_id in commits_to_pack {
        if should_interrupt.load(Ordering::Relaxed) {
            return Err(Error::Interrupted);
        }
        outcome.input_objects += 1;

        let (mut obj, mut location) = db.find(&commit_id, &mut buf1)?;
        let mut current_id = commit_id;

        // Follow tag chains so callers can hand us annotated tag tips.
        loop {
            match obj.kind {
                gix_object::Kind::Commit => break,
                gix_object::Kind::Tag => {
                    if seen.borrow_mut().insert(current_id) {
                        objects_counter.fetch_add(1, Ordering::Relaxed);
                        outcome.decoded_objects += 1;
                        out.push(output::Count::from_data(current_id, location.clone()));
                    }
                    current_id = TagRefIter::from_bytes(obj.data)
                        .target_id()
                        .expect("every tag has a target");
                    let tmp = db.find(&current_id, &mut buf1)?;
                    obj = tmp.0;
                    location = tmp.1;
                }
                gix_object::Kind::Blob | gix_object::Kind::Tree => {
                    let skip = match obj.kind {
                        gix_object::Kind::Blob => match filter {
                            ObjectFilter::BlobsNone | ObjectFilter::TreesNone => true,
                            ObjectFilter::BlobsAtLeast(limit) => obj.data.len() as u64 >= limit,
                            ObjectFilter::None => false,
                        },
                        gix_object::Kind::Tree => matches!(filter, ObjectFilter::TreesNone),
                        _ => false,
                    };
                    if seen.borrow_mut().insert(current_id) && !skip {
                        objects_counter.fetch_add(1, Ordering::Relaxed);
                        outcome.decoded_objects += 1;
                        out.push(output::Count::from_data(current_id, location.clone()));
                    }
                    break;
                }
            }
        }

        if !matches!(obj.kind, gix_object::Kind::Commit) {
            continue;
        }

        // Emit the commit itself.
        if seen.borrow_mut().insert(current_id) {
            objects_counter.fetch_add(1, Ordering::Relaxed);
            outcome.decoded_objects += 1;
            out.push(output::Count::from_data(current_id, location.clone()));
        } else {
            continue;
        }

        // Emit the commit's root tree and all reachable sub-trees and
        // blobs that aren't already in the seen set. Under
        // `TreesNone` we short-circuit here: the commit ships but we
        // skip the root tree and its entire subtree, matching git's
        // `filter=tree:0` semantics (commits-only clone).
        if matches!(filter, ObjectFilter::TreesNone) {
            continue;
        }
        let tree_id = CommitRefIter::from_bytes(obj.data)
            .tree_id()
            .expect("every commit has a tree");
        let skip_tree_walk = !seen.borrow_mut().insert(tree_id);
        if skip_tree_walk {
            continue;
        }
        let (tree_obj, tree_loc) = db.find(&tree_id, &mut buf2)?;
        objects_counter.fetch_add(1, Ordering::Relaxed);
        outcome.decoded_objects += 1;
        outcome.expanded_objects += 1;
        out.push(output::Count::from_data(tree_id, tree_loc));

        let seen_ref = &seen;
        let recording = RecordingObjects {
            inner: db,
            counter: &objects_counter,
            out: RefCell::new(std::mem::take(&mut out)),
            seen: seen_ref,
            decoded: std::cell::Cell::new(0),
            expanded: std::cell::Cell::new(0),
        };
        let mut traverse_delegate = NonTreeCollector {
            seen: seen_ref,
            non_trees: Vec::new(),
            filter,
        };
        gix_traverse::tree::breadthfirst(
            gix_object::TreeRefIter::from_bytes(tree_obj.data),
            &mut tree_state,
            &recording,
            &mut traverse_delegate,
        )
        .map_err(Error::TreeTraverse)?;
        out = recording.out.into_inner();
        outcome.decoded_objects += recording.decoded.get();
        outcome.expanded_objects += recording.expanded.get();

        for leaf_id in std::mem::take(&mut traverse_delegate.non_trees) {
            if should_interrupt.load(Ordering::Relaxed) {
                return Err(Error::Interrupted);
            }
            let loc = match filter {
                ObjectFilter::BlobsAtLeast(limit) => {
                    let (data, location) = db.find(&leaf_id, &mut buf2)?;
                    if data.data.len() as u64 >= limit {
                        continue;
                    }
                    location
                }
                _ => db.location_by_oid(&leaf_id, &mut buf2),
            };
            objects_counter.fetch_add(1, Ordering::Relaxed);
            outcome.decoded_objects += 1;
            out.push(output::Count::from_data(leaf_id, loc));
        }
    }

    outcome.total_objects = out.len();
    Ok((out, outcome))
}

/// Wrap a [`crate::Find`] so `gix_traverse::tree::breadthfirst`
/// can walk trees while we record each walked tree into the output
/// vector and bump the counters.
struct RecordingObjects<'a, F: crate::Find> {
    inner: &'a F,
    counter: &'a gix_features::progress::AtomicStep,
    out: RefCell<Vec<output::Count>>,
    seen: &'a RefCell<HashSet<ObjectId>>,
    decoded: std::cell::Cell<usize>,
    expanded: std::cell::Cell<usize>,
}

impl<F: crate::Find> gix_object::Find for RecordingObjects<'_, F> {
    fn try_find<'b>(&self, id: &oid, buffer: &'b mut Vec<u8>) -> Result<Option<Data<'b>>, gix_object::find::Error> {
        let maybe = self.inner.try_find(id, buffer)?;
        self.decoded.set(self.decoded.get() + 1);
        match maybe {
            None => Ok(None),
            Some((data, location)) => {
                // The tree walker inserts each visited tree id into the
                // visitor's seen set via `visit_tree`, but the emission
                // of `output::Count` for that tree has to happen here
                // where we have the pack location in hand.
                let mut seen = self.seen.borrow_mut();
                let inserted = seen.insert(id.to_owned());
                drop(seen);
                if inserted {
                    self.counter.fetch_add(1, Ordering::Relaxed);
                    self.expanded.set(self.expanded.get() + 1);
                    self.out
                        .borrow_mut()
                        .push(output::Count::from_data(id.to_owned(), location));
                }
                Ok(Some(data))
            }
        }
    }
}

/// Visitor for `gix_traverse::tree::breadthfirst` that records each
/// unseen non-tree (blob / commit-submodule) id into `non_trees`. Sub-
/// trees are inserted into `seen` as they are encountered so the
/// walker does not descend into them twice. The actual emission of
/// tree-typed [`output::Count`] entries happens inside
/// [`RecordingObjects::try_find`], which is called for each tree read
/// during the walk.
struct NonTreeCollector<'a> {
    seen: &'a RefCell<HashSet<ObjectId>>,
    non_trees: Vec<ObjectId>,
    filter: ObjectFilter,
}

impl gix_traverse::tree::Visit for NonTreeCollector<'_> {
    fn pop_back_tracked_path_and_set_current(&mut self) {}
    fn pop_front_tracked_path_and_set_current(&mut self) {}
    fn push_back_tracked_path_component(&mut self, _component: &gix_object::bstr::BStr) {}
    fn push_path_component(&mut self, _component: &gix_object::bstr::BStr) {}
    fn pop_path_component(&mut self) {}

    fn visit_tree(&mut self, entry: &gix_object::tree::EntryRef<'_>) -> gix_traverse::tree::visit::Action {
        // Only skip the descent when this subtree's OID has already
        // been seen (emitted) by `RecordingObjects::try_find` on an
        // earlier commit in `commits_to_pack`. CRUCIAL: we only *read*
        // `seen` here, we do not insert. Inserting would cause the
        // subsequent `find_tree_iter(..)` call that drives descent to
        // hit `RecordingObjects::try_find`, find the OID already in
        // `seen`, and silently skip emission of the `output::Count` —
        // leaving every subtree after the root missing from the pack.
        // The server's post-index-pack connectivity walk then fails
        // with `did not receive expected object <subtree-oid>`.
        // Emission + seen-insert must stay the `try_find` path's
        // responsibility alone.
        if self.seen.borrow().contains(entry.oid) {
            std::ops::ControlFlow::Continue(false)
        } else {
            std::ops::ControlFlow::Continue(true)
        }
    }

    fn visit_nontree(&mut self, entry: &gix_object::tree::EntryRef<'_>) -> gix_traverse::tree::visit::Action {
        if entry.mode.is_commit() {
            return std::ops::ControlFlow::Continue(true);
        }
        let oid = entry.oid.to_owned();
        let inserted = self.seen.borrow_mut().insert(oid);
        if inserted && !matches!(self.filter, ObjectFilter::BlobsNone) {
            self.non_trees.push(oid);
        }
        std::ops::ControlFlow::Continue(true)
    }
}
