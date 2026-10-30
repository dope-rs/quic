use o3::alloc;

use crate::conn::stream::state::streams::closed;
use crate::conn::stream::state::streams::closed::half::Kind;
use crate::conn::stream::state::streams::closed::lane;
use crate::conn::stream::state::streams::closed::storage::Pool;
use crate::conn::stream::state::streams::closed::storage::index::RawIndex;
use crate::conn::stream::state::streams::closed::tree::edit::Edit;
use crate::conn::stream::state::streams::closed::tree::entry::Entry;
use crate::conn::stream::state::streams::closed::tree::view::View;

/// Closed stream halves retained after their resident entries are released.
pub(in crate::conn) struct Set {
    storage: Pool,
    prefixes: [u64; closed::LANES],
    roots: [RawIndex; closed::LANES],
}

impl Set {
    pub(in crate::conn) fn try_new(plan: closed::Plan) -> Result<Self, alloc::Error> {
        Ok(Self {
            storage: Pool::try_new(plan)?,
            prefixes: [0; closed::LANES],
            roots: [RawIndex::NONE; closed::LANES],
        })
    }

    pub(in crate::conn) fn insert(&mut self, half: closed::Half) -> closed::Insertion {
        let number = half.number();
        match half.kind() {
            Kind::LocalBidiRecv => {
                self.with::<lane::LocalRecv, _>(|edit| Entry::insert(edit, number))
            }
            Kind::PeerBidiRecv => {
                self.with::<lane::PeerBidiRecv, _>(|edit| Entry::insert(edit, number))
            }
            Kind::PeerUniRecv => {
                self.with::<lane::PeerUniRecv, _>(|edit| Entry::insert(edit, number))
            }
            Kind::PeerBidiSend => {
                self.with::<lane::PeerBidiSend, _>(|edit| Entry::insert(edit, number))
            }
        }
    }

    pub(in crate::conn) fn contains(&self, half: closed::Half) -> bool {
        let number = half.number();
        match half.kind() {
            Kind::LocalBidiRecv => self.view::<lane::LocalRecv>().contains(number),
            Kind::PeerBidiRecv => self.view::<lane::PeerBidiRecv>().contains(number),
            Kind::PeerUniRecv => self.view::<lane::PeerUniRecv>().contains(number),
            Kind::PeerBidiSend => self.view::<lane::PeerBidiSend>().contains(number),
        }
    }

    fn with<L: lane::Lane, R>(&mut self, f: impl for<'owner> FnOnce(Edit<'owner, L>) -> R) -> R {
        let [local, bidi, uni, send] = &mut self.prefixes;
        let prefix = match L::KIND {
            Kind::LocalBidiRecv => local,
            Kind::PeerBidiRecv => bidi,
            Kind::PeerUniRecv => uni,
            Kind::PeerBidiSend => send,
        };
        let [local, bidi, uni, send] = &mut self.roots;
        let root = match L::KIND {
            Kind::LocalBidiRecv => local,
            Kind::PeerBidiRecv => bidi,
            Kind::PeerUniRecv => uni,
            Kind::PeerBidiSend => send,
        };
        f(Edit::new(prefix, root, &mut self.storage))
    }

    fn view<L: lane::Lane>(&self) -> View<'_, L> {
        let [local, bidi, uni, send] = &self.prefixes;
        let prefix = match L::KIND {
            Kind::LocalBidiRecv => local,
            Kind::PeerBidiRecv => bidi,
            Kind::PeerUniRecv => uni,
            Kind::PeerBidiSend => send,
        };
        let [local, bidi, uni, send] = self.roots;
        let root = match L::KIND {
            Kind::LocalBidiRecv => local,
            Kind::PeerBidiRecv => bidi,
            Kind::PeerUniRecv => uni,
            Kind::PeerBidiSend => send,
        };
        View::new(prefix, root, &self.storage)
    }
}

const _: () = assert!(std::mem::size_of::<Set>() == 9 * std::mem::size_of::<usize>());
