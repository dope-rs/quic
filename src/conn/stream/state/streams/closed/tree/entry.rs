use crate::conn::stream::state::streams::closed;
use crate::conn::stream::state::streams::closed::half::Number;
use crate::conn::stream::state::streams::closed::storage::index::Index;
use crate::conn::stream::state::streams::closed::storage::node::{Interval, Key, Set};
use crate::conn::stream::state::streams::closed::tree::edit::Edit;
use crate::conn::stream::state::streams::closed::tree::insert::Insert;
use crate::conn::stream::state::streams::closed::tree::path::{Depth, Path};
use crate::conn::stream::state::streams::closed::tree::remove::Remove;

pub(super) struct Location<'owner, L> {
    pub(super) depth: Depth,
    pub(super) node: Index<'owner, L>,
    pub(super) key: Key,
}

impl<L> Clone for Location<'_, L> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<L> Copy for Location<'_, L> {}

struct Candidate<'owner, L> {
    location: Location<'owner, L>,
    interval: Interval,
}

impl<'owner, L> Candidate<'owner, L> {
    fn set_start(self, edit: &mut Edit<'owner, L>, start: u64) -> Option<Set> {
        edit.node_mut(self.location.node)?
            .key_mut(self.location.key)?
            .start = start;
        Some(Set)
    }

    fn set_end(&self, edit: &mut Edit<'owner, L>, end: u64) -> Option<Set> {
        edit.node_mut(self.location.node)?
            .key_mut(self.location.key)?
            .end = end;
        Some(Set)
    }
}

pub(in crate::conn::stream::state::streams::closed) struct Entry<'owner, L> {
    edit: Edit<'owner, L>,
    path: Path<'owner, L>,
    left: Option<Candidate<'owner, L>>,
    right: Option<Candidate<'owner, L>>,
}

impl<'owner, L> Entry<'owner, L> {
    pub(in crate::conn::stream::state::streams::closed) fn insert(
        edit: Edit<'owner, L>,
        number: Number,
    ) -> closed::Insertion {
        let value = number.get();
        if value < *edit.prefix {
            return closed::Insertion::Present;
        }
        let next = number.next();
        if value == *edit.prefix {
            let Ok(mut entry) = Self::find(edit, next) else {
                return closed::Insertion::Unavailable;
            };
            *entry.edit.prefix = next;
            if let Some(first) = entry.left
                && first.interval.start == next
            {
                if Remove::new(&mut entry.edit, entry.path, first.location)
                    .commit()
                    .is_none()
                {
                    *entry.edit.prefix = value;
                    return closed::Insertion::Unavailable;
                }
                *entry.edit.prefix = first.interval.end;
            }
            return closed::Insertion::Inserted;
        }

        let Ok(mut entry) = Self::find(edit, value) else {
            return closed::Insertion::Unavailable;
        };
        if entry
            .left
            .as_ref()
            .is_some_and(|left| value < left.interval.end)
        {
            return closed::Insertion::Present;
        }
        let left = entry.left;
        let right = entry.right;
        let join_l = left.as_ref().is_some_and(|left| left.interval.end == value);
        let join_r = right
            .as_ref()
            .is_some_and(|right| right.interval.start == next);
        match (left, right, join_l, join_r) {
            (Some(left), Some(right), true, true) => {
                if left.set_end(&mut entry.edit, right.interval.end).is_none() {
                    return closed::Insertion::Unavailable;
                }
                if Remove::new(&mut entry.edit, entry.path, right.location)
                    .commit()
                    .is_none()
                {
                    if left.set_end(&mut entry.edit, value).is_none() {
                        return closed::Insertion::Unavailable;
                    }
                    return closed::Insertion::Unavailable;
                }
            }
            (Some(left), _, true, false) => {
                if left.set_end(&mut entry.edit, next).is_none() {
                    return closed::Insertion::Unavailable;
                }
            }
            (_, Some(right), false, true) => {
                if right.set_start(&mut entry.edit, value).is_none() {
                    return closed::Insertion::Unavailable;
                }
            }
            _ => {
                if Insert::new(
                    &mut entry.edit,
                    entry.path,
                    Interval {
                        start: value,
                        end: next,
                    },
                )
                .commit()
                .is_none()
                {
                    return closed::Insertion::Unavailable;
                }
            }
        }
        closed::Insertion::Inserted
    }

    fn find(edit: Edit<'owner, L>, start: u64) -> Result<Self, Unavailable> {
        let mut entry = Self {
            edit,
            path: Path::new(),
            left: None,
            right: None,
        };
        if entry.edit.root.is_none() {
            return Ok(entry);
        }
        let mut index = entry.edit.root.brand();
        for _ in 0..closed::MAX_LEVELS {
            let node = entry.edit.node(index).ok_or(Unavailable)?;
            let search = node.search(start);
            let left = search.left().map(|key| (key, node.key(key)));
            let right = search.right().map(|key| (key, node.key(key)));
            let leaf = node.is_leaf();
            let Some(vacant) = entry.path.vacant() else {
                return Err(Unavailable);
            };
            let depth = vacant.insert(index, search.gap());
            if let Some((key, interval)) = left {
                entry.left = Some(Candidate {
                    location: Location {
                        depth,
                        node: index,
                        key,
                    },
                    interval,
                });
            }
            if let Some((key, interval)) = right {
                entry.right = Some(Candidate {
                    location: Location {
                        depth,
                        node: index,
                        key,
                    },
                    interval,
                });
            }
            if leaf {
                return Ok(entry);
            }
            index = node.child(search.gap()).brand();
        }
        Err(Unavailable)
    }
}

struct Unavailable;
