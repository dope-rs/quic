use crate::{
    conn::{
        self,
        output::{
            self, cc, control,
            control::encode,
            delivery, journals,
            recovery::epochs,
            transmit::{Destination, Policy, builder, packet::plan::Plan},
        },
        stream::state::transmit,
        wire::{crypto::tx, path, tls},
    },
    proto::recovery::numbers,
    stream,
    wire::stream::Initiator,
};
use builder::pending::{draft, selected::Selected};
use journals::{controls, streams};
use o3::buffer;
use o3::depot::{array, index::Access};
use std::{mem, time};
use transmit::log::journal;

#[must_use]
pub(super) enum Records<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    Untracked(Input<'a, DOMAIN, B, D>),
    Tracked(journals::Reserve<Tracked<'a, DOMAIN, B, D>>),
}

#[repr(transparent)]
pub(super) struct Tracked<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
    journal::Reserve<Input<'a, DOMAIN, B, D>>,
);

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Tracked<'a, DOMAIN, B, D> {
    pub(super) fn new(owner: journal::Reserve<Input<'a, DOMAIN, B, D>>) -> Self {
        Self(owner)
    }

    fn owner(&self) -> &Input<'a, DOMAIN, B, D> {
        self.0.owner()
    }

    pub(super) fn cancel(self) -> Input<'a, DOMAIN, B, D> {
        self.0.cancel()
    }
}

pub(in crate::conn) struct Input<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    pub(in crate::conn::output::transmit::builder) connection: &'a mut conn::Machine<DOMAIN, B, D>,
    pub(in crate::conn::output::transmit::builder) controls:
        &'a mut array::Vec<encode::Written, { conn::PACKET_CONTROL_CAPACITY }>,
    pub(in crate::conn::output::transmit::builder) streams:
        &'a mut array::Vec<journal::Entry, { conn::PACKET_STREAM_CAPACITY }>,
    pub(in crate::conn::output::transmit::builder) crypto: &'a mut Option<tx::Commit>,
}

pub(in crate::conn) struct Preparation<'a> {
    pub(in crate::conn::output::transmit::builder) controls:
        &'a mut array::Vec<encode::Written, { conn::PACKET_CONTROL_CAPACITY }>,
    pub(in crate::conn::output::transmit::builder) control: &'a mut control::Pending,
    pub(in crate::conn::output::transmit::builder) path: &'a path::State,
    pub(in crate::conn::output::transmit::builder) scratch: &'a mut conn::Scratch,
}

pub(in crate::conn) struct Context<'a, const DOMAIN: u8, D: buffer::raw::Segment> {
    tx: &'a mut tx::Tx,
    keys: tls::Borrow<'a, DOMAIN>,
    spaces: &'a mut [numbers::PnSpace; 3],
    scratch: &'a mut conn::Scratch,
    streams: journal::Scope<'a, D>,
    control: &'a mut control::Pending,
    path: &'a mut path::State,
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Input<'a, DOMAIN, B, D> {
    pub(in crate::conn::output::transmit::builder) fn conn(&self) -> &conn::Machine<DOMAIN, B, D> {
        self.connection
    }

    pub(in crate::conn::output::transmit::builder) fn controls(&self) -> &[encode::Written] {
        self.controls.as_slice()
    }

    pub(in crate::conn::output::transmit::builder) fn target(
        &self,
        policy: &Policy,
        route: path::OutputRoute,
    ) -> Option<Destination> {
        builder::Builder::<DOMAIN, B, D>::target_for(self.connection, policy, route)
    }

    pub(in crate::conn::output::transmit::builder) fn into_scratch(self) -> &'a mut conn::Scratch {
        &mut self.connection.scratch
    }
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Records<'a, DOMAIN, B, D> {
    pub(super) fn conn(&self) -> &conn::Machine<DOMAIN, B, D> {
        match self {
            Self::Untracked(input) => input.connection,
            Self::Tracked(reserved) => reserved.owner().owner().connection,
        }
    }

    pub(super) fn controls(&self) -> &[encode::Written] {
        match self {
            Self::Untracked(input) => input.controls.as_slice(),
            Self::Tracked(reserved) => reserved.owner().owner().controls.as_slice(),
        }
    }

    pub(super) fn streams(&self) -> &[journal::Entry] {
        match self {
            Self::Untracked(input) => input.streams.as_slice(),
            Self::Tracked(reserved) => reserved.owner().owner().streams.as_slice(),
        }
    }

    pub(super) fn cancel(self) -> Input<'a, DOMAIN, B, D> {
        match self {
            Self::Untracked(input) => input,
            Self::Tracked(reserved) => reserved.cancel().cancel(),
        }
    }

    pub(super) fn parts(&mut self) -> (&mut tx::Tx, draft::Context<'_, DOMAIN>) {
        match self {
            Self::Untracked(input) => {
                let (tx, keys) = input.connection.handshake.parts();
                (
                    tx,
                    draft::Context {
                        keys,
                        spaces: &mut input.connection.egress.recovery.spaces,
                        scratch: &mut input.connection.scratch,
                    },
                )
            }
            Self::Tracked(reserved) => {
                let context = reserved.context();
                (
                    context.tx,
                    draft::Context {
                        keys: context.keys,
                        spaces: context.spaces,
                        scratch: context.scratch,
                    },
                )
            }
        }
    }

    pub(super) fn commit(
        self,
        mut plan: Plan,
        crypto: Option<delivery::Handle<delivery::Crypto>>,
        amp: output::AmpSent,
        now: time::Instant,
    ) {
        use output::Consumption;

        let queued = plan.is_queued();
        let ack = plan.flags.ack.take();
        let included = ack.is_included();
        let conn = self.record(&plan, crypto, now);
        ack.apply(&mut conn.receive.packet_numbers);
        let epoch = plan.epoch;
        let number = plan.packet_number.auth().protected();
        if plan.is_tracked() && plan.flags.is_eliciting() && plan.flags.is_in_flight() {
            let space = epoch.bind_mut(&mut conn.egress.recovery.spaces);
            space.time_of_last_ack_eliciting = Some(now);
        }
        conn.egress.activity.commit_amp(amp);
        let bytes = plan.bytes as u64;
        let flight = plan.is_tracked() && plan.flags.is_in_flight();
        let probe = if flight {
            plan.path
                .pmtud_probe
                .and_then(|size| cc::Packet::from_epoch(epoch, number).map(|packet| (packet, size)))
        } else {
            None
        };
        conn.egress.cc.packet_sent(bytes, flight, now, probe);
        if plan.flags.is_pto_probe() {
            match conn.egress.recovery.probe.allowance.consume() {
                Consumption::Exhausted | Consumption::Drained => {
                    conn.egress.recovery.probe.epoch = None;
                }
                Consumption::Remaining => {}
            }
        }
        if plan.flags.is_eliciting() && !conn.egress.activity.ack_eliciting_sent_since_last_receive
        {
            conn.egress.activity.last_activity = Some(now);
            conn.egress.activity.ack_eliciting_sent_since_last_receive = true;
        }
        if plan.flags.is_close() {
            conn.egress.lifecycle.pending_close = None;
            conn.egress.lifecycle.state = crate::conn::State::Closed;
        }
        if epoch == crate::conn::Epoch::Application && included {
            conn.handshake.keys.confirm();
        }
        let effects = conn
            .path
            .transmit(plan.path.route.path(), plan.bytes, &conn.control);
        conn.peer.reconcile.merge(effects);
        if queued {
            conn.egress.datagrams.pop_front();
        }
        if epoch == conn::Epoch::Handshake
            && matches!(conn.peer.local, Initiator::Client)
            && conn.handshake.keys.long.initial().is_some()
        {
            epochs::Epochs::new(conn).discard(conn::Epoch::Initial);
            conn.peer.reconcile.insert(conn::Effects::RECOVERY);
        }
    }

    fn record(
        self,
        plan: &Plan,
        crypto: Option<delivery::Handle<delivery::Crypto>>,
        now: time::Instant,
    ) -> &'a mut conn::Machine<DOMAIN, B, D> {
        match self {
            Self::Untracked(input) => input.connection,
            Self::Tracked(reserved) => {
                reserved
                    .commit(
                        journals::Transmission::new(
                            plan.flags.is_early(),
                            plan.flags.is_eliciting(),
                            plan.flags.is_in_flight(),
                        ),
                        now,
                        plan.bytes,
                        crypto,
                    )
                    .cancel()
                    .connection
            }
        }
    }
}

pub(in crate::conn) struct Root<'a, const DOMAIN: u8> {
    table: &'a mut journals::Table,
    controls: &'a mut array::Vec<encode::Written, { conn::PACKET_CONTROL_CAPACITY }>,
    tx: &'a mut tx::Tx,
    keys: tls::Borrow<'a, DOMAIN>,
    spaces: &'a mut [numbers::PnSpace; 3],
    scratch: &'a mut conn::Scratch,
    control: &'a mut control::Pending,
    path: &'a mut path::State,
}

// SAFETY: Input retains the complete original connection and both bounded
// input lists; its disjoint context cannot mutate transmit state or selections.
unsafe impl<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> journal::raw::Owner
    for Input<'_, DOMAIN, B, D>
{
    type Send = D;
    type Selection = tx::Commit;
    type Context<'a>
        = Root<'a, DOMAIN>
    where
        Self: 'a;

    fn selection(&mut self) -> &mut Option<Self::Selection> {
        self.crypto
    }

    fn scratch(&mut self) -> &mut conn::Scratch {
        &mut self.connection.scratch
    }

    fn discard(&mut self) {
        drop(self.controls.drain());
        drop(self.streams.drain());
    }

    fn parts(
        &mut self,
    ) -> (
        &mut transmit::State<D>,
        &mut array::Vec<journal::Entry, { conn::PACKET_STREAM_CAPACITY }>,
        Self::Context<'_>,
    ) {
        let conn = &mut *self.connection;
        let (tx, keys) = conn.handshake.parts();
        (
            &mut conn.streams.state.transmit,
            self.streams,
            Root {
                table: &mut conn.egress.recovery.packet_journals,
                controls: self.controls,
                tx,
                keys,
                spaces: &mut conn.egress.recovery.spaces,
                scratch: &mut conn.scratch,
                control: &mut conn.control,
                path: &mut conn.path,
            },
        )
    }
}

// SAFETY: only the private packet admission constructs Tracked from its
// original stream reservation. No caller can reopen its control selections;
// publication consumes the retained lists through the scoped slot iterator.
unsafe impl<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> journals::raw::Owner
    for Tracked<'_, DOMAIN, B, D>
{
    type Control = encode::Written;
    type Context<'a>
        = Context<'a, DOMAIN, D>
    where
        Self: 'a;

    fn demand(&self) -> journals::Demand {
        journals::Demand::new(self.owner().controls, self.owner().streams)
    }

    fn parts(
        &mut self,
    ) -> (
        &mut journals::Table,
        &mut array::Vec<encode::Written, { conn::PACKET_CONTROL_CAPACITY }>,
        Self::Context<'_>,
    ) {
        let (scope, root) = journal::Reserve::parts(&mut self.0);
        (
            root.table,
            root.controls,
            Context {
                tx: root.tx,
                keys: root.keys,
                spaces: root.spaces,
                scratch: root.scratch,
                streams: scope,
                control: root.control,
                path: root.path,
            },
        )
    }

    fn write<'a>(
        mut writer: journals::Entry<'a>,
        mut ctrl: journals::Slots<'a, Self::Control, controls::Tag>,
        strm: journals::Supply<streams::Tag>,
        context: Self::Context<'a>,
    ) where
        Self: 'a,
    {
        use control::journal;

        context
            .streams
            .write(strm, |slot, handle| writer.push_stream(slot, handle));
        while let Some((delivery, slot)) = ctrl.next() {
            let sent = delivery.sent();
            let live = Access::into_live(Selected {
                owner: context.control,
                selected: delivery,
            });
            let live =
                unsafe { live.map(|(owner, key)| ((owner.owner, owner.selected.state()), key)) };
            let handle = journal::commit(live);
            // SAFETY: this complete packet owner retains the same encoded stores.
            // Each response deletion updates all still-unread position receipts.
            unsafe {
                encode::raw::Sent::into(
                    sent,
                    &mut *context.control,
                    &mut context.path.local,
                    ctrl.as_mut_slice(),
                )
            };
            writer.push_control(slot, handle);
        }
    }
}

const _: () = assert!(
    mem::size_of::<Context<'static, 0, o3::buffer::resident::Shared<'static>>>()
        == 10 * mem::size_of::<usize>()
);
