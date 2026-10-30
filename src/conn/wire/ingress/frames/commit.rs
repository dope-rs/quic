use crate::conn::wire::ingress::events;
use crate::errors::detail::{self, Diagnostic};
use crate::wire::stream::Direction;
use crate::{
    conn,
    proto::param,
    stream::{self, release},
    wire::frame,
};
use conn::output::recovery;
use conn::stream::state::{receive, transmit};
use conn::wire::ingress::{frames, packet};
use conn::wire::{crypto::chunks, path, tls};
use events::Observe as _;
use frames::{check, plan, record, sources, streams};
use o3::{alloc, buffer, depot::capacity};
use path::peer;
use receive::input;
use recovery::{ack, delivery, early, epochs, shift, timer};
use std::time::Duration;
pub(super) struct Commit<'a, 'b, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    packet: &'a mut packet::Packet<'b, DOMAIN, B, D>,
}
impl<'a, 'b, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Commit<'a, 'b, DOMAIN, B, D>
{
    pub(super) fn new(packet: &'a mut packet::Packet<'b, DOMAIN, B, D>) -> Self {
        Self { packet }
    }
    pub(super) fn try_process<S, E>(
        &mut self,
        meta: frames::PacketMeta,
        cid: Option<frames::PacketCid<'_>>,
        plan: plan::Plan<'_, '_, '_, '_, '_, '_, '_, '_, '_>,
        source: S,
        proof: &mut E,
    ) -> Result<frames::Disposition, conn::Error>
    where
        S: sources::Source<B>,
        E: events::Sink,
    {
        let epoch = meta.epoch();
        let now = meta.now;
        let (conn, past) = self.packet.state();
        let conn::Machine {
            egress,
            control: ctrl,
            handshake: hs,
            path,
            streams: state,
            receive: rx,
            peer,
            ..
        } = &mut *conn;
        let queue = &mut state.events;
        let local = peer.local;
        let route = path.ingress().response();
        ctrl.replies().retain();
        let grant = match plan.try_reserve(&mut state.state) {
            Ok(grant) => grant,
            Err(error) => {
                return {
                    let code = error.close_code();
                    if let Some(observer) = proof.observer() {
                        observer.observe(&Diagnostic::Plan(error));
                    }
                    code.map_or(Ok(frames::Disposition::Drop), Err)
                };
            }
        };
        let bytes = grant.bytes();
        let evcap = grant.events();
        let grant = match grant.prepare(&mut rx.crypto, epoch) {
            Ok(grant) => grant,
            Err(chunks::Failure::Connection(error)) => return Err(error),
            Err(chunks::Failure::Allocation(alloc::Exhausted)) => {
                return Ok(frames::Disposition::Drop);
            }
        };
        let mut discard = false;
        let mut done = frames::CommitState::new(egress.lifecycle.state);
        let result = grant.commit(|work, input, state, credit, token| {
            let body = input.body();
            let frames = input.frames();
            check::validate(
                state,
                frames,
                epoch.bind(&egress.recovery.spaces).next_pn,
                cid.as_ref(),
            )?;
            if meta.kind() == frames::PacketKind::ONE_RTT
                && frames.iter().any(|record| !record.is_probing())
            {
                path.observe(meta.number());
            }
            let Some(mut events) = queue.reserve(evcap) else {
                return Ok(frames::Disposition::Drop);
            };
            let (applied, control);
            let ready = match input.prepare(source, bytes, work, state, token) {
                Ok(store) => store,
                Err(error) => {
                    if let Some(observer) = proof.observer() {
                        observer.observe(&Diagnostic::Preparation(error));
                    }
                    return Ok(frames::Disposition::Drop);
                }
            };
            let segs = &mut work.segments;
            let parts = &mut work.parts;
            let frames = ready.frames();
            let dgrams = match ready.try_datagram().and_then(|dgrams| {
                let count = dgrams.len();
                rx.datagrams
                    .try_reserve(count)
                    .map_err(|error| detail::Unavailable::Queue {
                        error,
                        requested: count,
                    })?;
                Ok(dgrams)
            }) {
                Ok(dgrams) => dgrams,
                Err(error) => {
                    if let Some(observer) = proof.observer() {
                        observer.observe(&Diagnostic::Datagram(error));
                    }
                    return Ok(frames::Disposition::Drop);
                }
            };
            let updated = {
                use conn::stream::State;
                let State {
                    resident, receive, ..
                } = &mut **state;
                receive.map.scope(resident, &mut work.streams, |scope| {
                    streams::Streams::try_new(scope, &ready, segs, parts)?
                        .try_apply(&token, &mut events)
                })
            };
            match updated {
                Ok(()) => {}
                Err(error) => {
                    if let Some(observer) = proof.observer() {
                        observer.observe(&Diagnostic::Streams(error));
                    }
                    return Ok(frames::Disposition::Drop);
                }
            }
            state.receive.connection_window.record(token, credit);
            done.applied(frames, evcap != 0);
            let mut dgrams = dgrams.into_iter();
            for record in frames.iter() {
                if let frame::View::PathResponse { data } = record.view() {
                    match path.try_respond(*data, ctrl) {
                        Ok(()) => {}
                        Err(
                            capacity::Reason::Full
                            | capacity::Reason::Allocation(
                                alloc::Error::Exhausted | alloc::Error::Overflow,
                            ),
                        ) => return Ok(frames::Disposition::Drop),
                    }
                }
            }
            for record in frames.iter() {
                if let frame::View::PathChallenge { data } = record.view() {
                    use path::probe::Error;
                    match ctrl.replies().try_queue(*data, route) {
                        Ok(()) => {}
                        Err(
                            Error::Capacity { .. }
                            | Error::Keys { .. }
                            | Error::State { .. }
                            | Error::Duplicate { .. },
                        ) => {
                            return Ok(frames::Disposition::Drop);
                        }
                    }
                }
            }
            (applied, control) = ready.controls(|control| {
                match control {
                    sources::Control::Crypto(chunk) => {
                        chunks::accept(chunk, |msg| {
                            let step =
                                hs.read(epoch, msg, &mut |error| proof.certificate(error), |hs| {
                                    done.early_data_rejected = true;
                                    early::EarlyData::new(
                                        delivery::Graph::new(
                                            egress,
                                            ctrl,
                                            hs,
                                            state,
                                            events.events(),
                                        ),
                                        release::Ignore,
                                    )
                                    .try_reject(now)
                                })?;
                            if let Some(finish) = step.done {
                                (tls::Finish {
                                    egress,
                                    control: ctrl,
                                    completion: finish,
                                    path,
                                    streams: state,
                                    params: &mut peer.transport_params,
                                    local,
                                })
                                .apply()?;
                            }
                            if step.keys_changed {
                                done.recovery_deadline_requires_exact = true;
                                timer::Timer::try_update(egress, &hs.keys, local, now)?;
                            }
                            Ok(())
                        })?;
                    }
                    sources::Control::Frame(record::Operation::Drop(parsed)) => match parsed {
                        frame::View::Ack {
                            delay,
                            additional_ranges: ranges,
                            ..
                        } => {
                            let ranges = ranges.resolve(&body);
                            let last = ranges.largest();
                            let space = epoch.bind_mut(&mut egress.recovery.spaces);
                            let advanced = space.largest_acked.is_none_or(|prior| last > prior);
                            if advanced {
                                space.largest_acked = Some(last);
                            }
                            if epoch == conn::Epoch::Application {
                                hs.keys.acknowledge(last, now);
                            }
                            let wait = if epoch == conn::Epoch::Application
                                && egress.lifecycle.handshake_confirmed
                            {
                                let shift = match &peer.transport_params {
                                    Some(params) => params.timing().ack_exponent(),
                                    None => param::DEFAULT_ACK_DELAY_EXPONENT,
                                };
                                let max = egress.recovery.peer_max_ack_delay;
                                let delay = match delay.get().checked_mul(1_u64 << shift) {
                                    Some(delay) => Duration::from_micros(delay),
                                    None => max,
                                };
                                delay.min(max)
                            } else {
                                Duration::ZERO
                            };
                            done.recovery_deadline_changed = true;
                            ack::Ack::new(
                                delivery::Graph::new(egress, ctrl, hs, state, events.events()),
                                release::Forward::new(proof),
                            )
                            .try_apply(
                                epoch,
                                ack::Receipt {
                                    delay: wait,
                                    ranges,
                                    advanced,
                                },
                                now,
                            )?;
                        }
                        frame::View::HandshakeDone => {
                            egress.lifecycle.handshake_confirmed = true;
                            epochs::Transition::new(egress, hs).discard(conn::Epoch::Initial);
                            epochs::Transition::new(egress, hs).discard(conn::Epoch::Handshake);
                            past.confirm();
                            discard = true;
                            done.recovery_deadline_requires_exact = true;
                            timer::Timer::try_update(egress, &hs.keys, local, now)?;
                        }
                        frame::View::NewToken { token, .. } => {
                            let Ok(token) = body.resolve(token.clone()) else {
                                return Ok(frames::Disposition::Drop);
                            };
                            hs.peer.store_token(token, path.ingress().peer());
                        }
                        frame::View::ConnectionClose { .. } => {
                            egress.lifecycle.state = conn::State::Closed;
                        }
                        frame::View::NewConnectionId { notice, retire } => {
                            match path.accept(notice.clone(), *retire, ctrl) {
                                Ok(()) => {}
                                Err(peer::Error::Capacity(error)) => {
                                    if let Some(observer) = proof.observer() {
                                        observer.observe(&Diagnostic::Peer(error));
                                    }
                                    return Ok(frames::Disposition::Drop);
                                }
                                Err(peer::Error::Connection(error)) => return Err(error),
                            }
                        }
                        frame::View::RetireConnectionId {
                            sequence_number: seq,
                        } => {
                            let Some(route) = cid else {
                                return Ok(frames::Disposition::Drop);
                            };
                            let issued = path.local.retire(seq, route.routed, route.bytes, ctrl)?;
                            egress.derived.advertise(issued);
                        }
                        frame::View::PathChallenge { .. } => {}
                        frame::View::MaxData { maximum_data: max } => {
                            state.transmit.peer.data_credit.raise(max, ctrl);
                        }
                        frame::View::MaxStreamData {
                            stream_id: id,
                            maximum_stream_data: max,
                        } => {
                            state.open_peer(id);
                            if let Err(error) = transmit::Commit::new(state).try_credit(
                                id,
                                max,
                                peer.transport_params.as_ref(),
                                ctrl,
                            ) {
                                if let Some(observer) = proof.observer() {
                                    observer.observe(&Diagnostic::Send { id, error });
                                }
                                return Ok(frames::Disposition::Drop);
                            }
                        }
                        frame::View::StreamDataBlocked { stream_id: id, .. } => {
                            state.open_peer(id);
                        }
                        frame::View::MaxStreams {
                            direction: dir,
                            max_streams: max,
                        } => {
                            let max = max.get();
                            let limit = match dir {
                                Direction::Bidi => &mut state.local_initiated.peer_max[0],
                                Direction::Uni => &mut state.local_initiated.peer_max[1],
                            };
                            *limit = (*limit).max(max);
                        }
                        frame::View::PathResponse { .. } => {}
                        frame::View::Crypto { .. }
                        | frame::View::Padding
                        | frame::View::Ping
                        | frame::View::Datagram { .. }
                        | frame::View::Stream { .. }
                        | frame::View::ResetStream { .. }
                        | frame::View::StopSending { .. }
                        | frame::View::DataBlocked { .. }
                        | frame::View::StreamsBlocked { .. } => {}
                    },
                    sources::Control::Frame(
                        record::Operation::Datagram
                        | record::Operation::Stream { .. }
                        | record::Operation::StreamTransient { .. }
                        | record::Operation::Reset(_)
                        | record::Operation::Stop { .. },
                    ) => {}
                }
                Ok::<_, conn::Error>(frames::Disposition::Commit)
            });
            if matches!(control?, frames::Disposition::Drop) {
                return Ok(frames::Disposition::Drop);
            }
            for op in applied.operations() {
                match op {
                    record::Operation::Drop(_) => {}
                    record::Operation::Datagram => {
                        let Some(bytes) = dgrams.next() else {
                            return Ok(frames::Disposition::Drop);
                        };
                        rx.datagrams.push_back(bytes);
                    }
                    record::Operation::Stream { id, .. } => {
                        state.open_peer(id);
                    }
                    record::Operation::StreamTransient {
                        key,
                        id,
                        offset,
                        plan,
                        boundary,
                    } => {
                        state.open_peer(id);
                        state.commit_seen(
                            &token,
                            input::Input::new(key, id, offset, plan, boundary),
                            &mut events,
                        );
                    }
                    record::Operation::Reset(reset) => {
                        state.open_peer(reset.id);
                        state.commit_reset(reset, ctrl, &mut events);
                    }
                    record::Operation::Stop {
                        key,
                        id,
                        error_code: code,
                    } => {
                        state.open_peer(id);
                        if let Err(error) = transmit::Commit::new(state).try_stop(
                            key,
                            id,
                            code,
                            peer.transport_params.as_ref(),
                            transmit::Effects::new(ctrl, &mut events, proof),
                        ) {
                            if let Some(observer) = proof.observer() {
                                observer.observe(&Diagnostic::Send { id, error });
                            }
                            return Ok(frames::Disposition::Drop);
                        }
                    }
                }
            }
            if matches!(
                path.try_migrate(ctrl)
                    .map_err(|reason| conn::Error::Path(path::Error::Peer(reason)))?,
                path::Migration::Committed
            ) {
                done.path_migrated = true;
                shift::Shift::new(
                    delivery::Graph::new(egress, ctrl, hs, state, events.events()),
                    release::Ignore,
                )
                .try_commit(now)?;
            }
            Ok(frames::Disposition::Commit)
        });
        if discard {
            rx.crypto.discard(conn::Epoch::Initial);
            rx.crypto.discard(conn::Epoch::Handshake);
        }
        let effects = done.finish(egress.lifecycle.state);
        self.packet.record(effects);
        result
    }
}
