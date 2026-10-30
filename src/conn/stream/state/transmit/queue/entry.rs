use crate::stream::{outbound, send::admit};

use std::ops;

use crate::conn::output::control::{self, kind};
use crate::conn::stream::resident::slot;
use crate::conn::stream::state::streams;
use crate::conn::stream::state::transmit::log;
use crate::conn::stream::state::transmit::queue::{self, Phase};
use crate::proto::param;
use crate::wire::stream::Direction;
use crate::wire::varint;
use control::owner;

/// Mutable state for one live stream send queue.
pub(in crate::conn) struct Entry {
    pub(super) stream: outbound::Sender,
    pub(super) credit: queue::Credit<kind::StreamBlock>,
    pub(super) delivery_group: Option<log::GroupId>,
    pub(super) reset_stream: owner::Signal<kind::ResetStream>,
}

impl Entry {
    pub(in crate::conn) fn limit(
        peer: Option<&param::Set>,
        stream: streams::Relative,
    ) -> varint::VarInt {
        let Some(peer) = peer else {
            return varint::VarInt::ZERO;
        };
        let flow = peer.flow();
        match (stream.direction(), stream.is_local()) {
            (Direction::Uni, true) => flow.stream_uni(),
            (Direction::Uni, false) => varint::VarInt::ZERO,
            (Direction::Bidi, true) => flow.remote_bidi(),
            (Direction::Bidi, false) => flow.local_bidi(),
        }
    }

    pub(in crate::conn) fn credit(&self) -> &queue::Credit<kind::StreamBlock> {
        &self.credit
    }

    pub(in crate::conn) fn is_deferred(&self) -> bool {
        self.reset_stream.is_deferred()
    }

    pub(super) fn deferred(
        &mut self,
    ) -> Option<(owner::Deferred<'_, kind::ResetStream>, varint::VarInt)> {
        Some((
            self.reset_stream.deferred()?,
            self.stream.view().next_offset(),
        ))
    }

    pub(in crate::conn) fn is_reset(&self) -> bool {
        !self.reset_stream.is_empty()
    }

    pub(in crate::conn) fn phase(&self) -> Phase {
        if self.is_reset() {
            return Phase::Reset;
        }
        match self.stream.finish() {
            outbound::Finish::More => Phase::Open,
            outbound::Finish::Marked => Phase::Marked,
            outbound::Finish::Sent => Phase::Sent,
            outbound::Finish::Acked => Phase::Acked,
        }
    }

    pub(super) fn open(&mut self) -> Result<outbound::Open<'_>, admit::Cause> {
        if self.is_reset() {
            return Err(admit::Cause::Reset);
        }
        self.stream.open().ok_or(admit::Cause::Finished)
    }
}

impl slot::Reusable for Entry {
    type Init = varint::VarInt;

    fn new(init: Self::Init) -> Self {
        Self {
            stream: outbound::Sender::default(),
            credit: queue::Credit::new(init),
            delivery_group: None,
            reset_stream: owner::Signal::new(),
        }
    }

    fn reuse(&mut self, init: Self::Init) {
        self.credit = queue::Credit::new(init);
    }
}

impl ops::Deref for Entry {
    type Target = outbound::Sender;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

const _: () = assert!(
    std::mem::size_of::<Entry>()
        == std::mem::size_of::<outbound::Sender>() + 4 * std::mem::size_of::<u64>()
);
