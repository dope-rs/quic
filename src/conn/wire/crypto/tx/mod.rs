use o3::alloc;

use crate::conn;
use crate::conn::machine::storage::capacity;
use crate::conn::output::delivery;

pub(in crate::conn::wire) mod bytes;
mod commit;
mod queues;
pub(in crate::conn) mod raw;
mod stores;
pub(in crate::conn) use commit::Commit;
pub(in crate::conn::wire::crypto::tx) use queues::{Flights, Ready};
pub(in crate::conn) use stores::table::Prepared;

/// Borrowed CRYPTO range selected from one immutable epoch byte store.
pub(in crate::conn) struct Selection<'tx> {
    pub(in crate::conn) commit: Commit,
    pub(in crate::conn) data: &'tx [u8],
}

/// Coordinates outbound TLS bytes with their independent delivery journal.
/// Selected packets borrow the byte owner; ACK/loss mutate only after that
/// borrow ends, and no record can outlive its generation-checked identity.
pub(in crate::conn) struct Tx {
    pub(in crate::conn::wire) bytes: bytes::Store,
    deliveries: stores::Set,
}

impl Tx {
    pub(in crate::conn) fn try_new(
        limit: capacity::Capacity<capacity::Crypto>,
    ) -> Result<Self, alloc::Error> {
        Ok(Self {
            bytes: bytes::Store::new(),
            deliveries: stores::Set::try_new(limit)?,
        })
    }

    pub(in crate::conn) fn has_sendable(&self, epoch: conn::Epoch) -> bool {
        self.deliveries.has_ready(epoch) || self.bytes.has_unsent(epoch)
    }

    pub(in crate::conn) fn select<'tx>(
        &'tx self,
        epoch: conn::Epoch,
        limit: impl FnOnce(delivery::Crypto) -> usize,
    ) -> Option<Selection<'tx>> {
        let ready = self.deliveries.ready(epoch);
        let range = ready.map_or_else(|| self.bytes.peek_unsent(epoch), |item| Some(item.1))?;
        let (record, rest) = range.split(limit(range))?;
        let data = self.bytes.slice(epoch, record)?;
        let commit = Commit(match ready {
            Some((key, _)) => commit::State::Ready { key, record, rest },
            None => commit::State::Fresh { epoch, record },
        });
        Some(Selection { commit, data })
    }

    pub(in crate::conn) fn select_probe<'tx>(
        &'tx self,
        epoch: conn::Epoch,
        limit: impl FnOnce(delivery::Crypto) -> usize,
    ) -> Option<Selection<'tx>> {
        let commit = self.deliveries.probe(epoch)?;
        let record = commit.record();
        if record.len() > limit(record) {
            return None;
        }
        Some(Selection {
            commit,
            data: self.bytes.slice(epoch, record)?,
        })
    }

    pub(in crate::conn) fn acknowledge(&mut self, handle: delivery::Handle<delivery::Crypto>) {
        let Some(ack): Option<stores::Acknowledged> = self.deliveries.acknowledge(handle) else {
            return;
        };
        if ack.epoch != conn::Epoch::Initial
            && let Some(offset) = ack.reclaim
        {
            self.bytes.reclaim_to(ack.epoch, offset);
        }
    }

    pub(in crate::conn) fn lose(&mut self, handle: delivery::Handle<delivery::Crypto>) {
        self.deliveries.lose(handle)
    }

    pub(in crate::conn) fn arm_probes(&mut self, epoch: conn::Epoch) {
        self.deliveries.arm_probes(epoch)
    }

    pub(in crate::conn) fn discard(&mut self, epoch: conn::Epoch) {
        self.deliveries.clear(epoch);
        self.bytes.discard(epoch);
    }

    pub(in crate::conn) fn retry(&mut self) {
        self.deliveries.clear(conn::Epoch::Initial);
        self.bytes.retry(conn::Epoch::Initial);
    }

    pub(in crate::conn) fn bytes(&self, epoch: conn::Epoch) -> &[u8] {
        self.bytes.bytes(epoch)
    }
}

/// Compile-time proof that the ownership boundary adds no runtime layout.
const _: () = assert!(
    std::mem::size_of::<Tx>()
        == std::mem::size_of::<bytes::Store>() + std::mem::size_of::<stores::Set>()
);
