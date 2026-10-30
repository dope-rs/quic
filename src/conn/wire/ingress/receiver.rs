use crate::conn::wire::ingress::events;
use o3::buffer;
use std::time;

use crate::conn::wire::{ingress, path};
use crate::conn::{self, machine};
use crate::proto::recovery::pmtud;
use crate::stream;
use crate::wire::packet::{self, long, short};
use crate::wire::stream::Initiator;
use ingress::{bodies, retry};
use long::sequence::{self, Sequence as _};
use path::reset;

enum Reset {
    Received,
    Absent,
}

pub(in crate::conn) struct Receiver<
    'a,
    'b,
    const DOMAIN: u8,
    B: stream::Recv,
    const RECONCILE: bool,
    D: buffer::raw::Segment,
    E,
> {
    input: &'a mut ingress::Input<'b, DOMAIN, B, RECONCILE, D>,
    now: time::Instant,
    sink: &'a mut E,
}

impl<'a, 'b, const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment, E>
    Receiver<'a, 'b, DOMAIN, B, RECONCILE, D, E>
{
    pub(in crate::conn) fn new(
        input: &'a mut ingress::Input<'b, DOMAIN, B, RECONCILE, D>,
        now: time::Instant,
        sink: &'a mut E,
    ) -> Self {
        Self { input, now, sink }
    }

    pub(in crate::conn) fn run<P, S>(self, mut packet: P, policy: S) -> Result<(), conn::Error>
    where
        P: long::Buffer,
        for<'p> &'p mut P: sequence::Sequence,
        S: bodies::Policy<P, DOMAIN, B, RECONCILE, D>,
        for<'p> S:
            bodies::Policy<<&'p mut P as sequence::Sequence>::First, DOMAIN, B, RECONCILE, D>,
        E: events::Sink,
    {
        let Self { input, now, sink } = self;
        let bytes = packet.as_ref();
        let Some(&first) = bytes.first() else {
            return Ok(());
        };
        let len = bytes.len();
        if len > pmtud::MAX_PMTU as usize {
            return Err(conn::Error::PacketCeiling);
        }
        if !input.connection.egress.activity.peer_address_validated
            && let Some(credit) = input.connection.path.ingress().credit(len)
        {
            let received = input
                .connection
                .egress
                .activity
                .amplification_received
                .checked_add(credit.bytes() as u64);
            if let Some(received) = received {
                input.connection.egress.activity.amplification_received = received;
            }
            input
                .context
                .record(conn::Effects::from_bits(conn::Effects::TRANSMIT));
        }
        if first & packet::FIXED_BIT == 0 {
            return Ok(());
        }
        let accept =
            matches!(input.connection.peer.local, Initiator::Client) || long::is_initial_size(len);
        while let Some(&first) = packet.as_ref().first() {
            if first & 0x80 == 0 {
                if first & 0x40 == 0 {
                    break;
                }
                let pto = match input.connection.try_pto() {
                    Ok((_, pto)) => pto,
                    Err(error) => return input.reject(error.into()),
                };
                let cid = input.connection.path.local.id();
                let width = cid.as_ref_id().length();
                let next = conn::Epoch::Application
                    .bind(&input.connection.receive.packet_numbers.spaces)
                    .expected_pn();
                let Some(key) = input.connection.handshake.keys.read() else {
                    Self::reset(input, packet.as_ref());
                    return Ok(());
                };
                let sealed = match short::Protected::parse(packet, width) {
                    Ok(sealed) => sealed,
                    Err(fail) => {
                        let (packet, error) = fail.into_parts();
                        return Self::short_fail(input, packet.as_ref(), conn::Error::Short(error));
                    }
                };
                let opened = match key.open(sealed, next, now, pto) {
                    Ok(opened) => opened,
                    Err(fail) => {
                        let (packet, error) = fail.into_parts();
                        return Self::short_fail(input, packet.as_ref(), error);
                    }
                };
                input.connection.handshake.keys.drop_early();
                policy.try_process(input, bodies::Packet::one_rtt(opened, now, pto), sink)?;
                break;
            }
            if first & 0x30 == 0x30 {
                retry::Retry::new(input).receive(packet.as_ref(), now)?;
                break;
            }
            let long = (&mut packet).first().map_err(conn::Error::Long)?;
            match long {
                long::Parsed::Initial(long) if accept => {
                    if let Some(key) = input.connection.handshake.keys.initial() {
                        let peer = (matches!(input.connection.peer.local, Initiator::Client)
                            && input.connection.path.origin.peer_first_scid.is_none())
                        .then(|| long.scid());
                        let next = conn::Epoch::Initial
                            .bind(&input.connection.receive.packet_numbers.spaces)
                            .expected_pn();
                        let open = match key.decrypt(long, next) {
                            Ok(open) => open,
                            Err(error) => return input.reject(error),
                        };
                        if let Some(cid) = peer {
                            input.connection.path.set_peer(cid)?;
                            input
                                .context
                                .record(conn::Effects::from_bits(conn::Effects::TRANSMIT));
                        }
                        policy.try_process(input, bodies::Packet::long(open, now), sink)?;
                    }
                }
                long::Parsed::Initial(_) => {}
                long::Parsed::ZeroRtt(long) => {
                    if let Some(key) = input.connection.handshake.keys.early() {
                        let next = conn::Epoch::Application
                            .bind(&input.connection.receive.packet_numbers.spaces)
                            .expected_pn();
                        let open = match key.decrypt(long, next) {
                            Ok(open) => open,
                            Err(error) => return input.reject(error),
                        };
                        policy.try_process(input, bodies::Packet::long(open, now), sink)?;
                    }
                }
                long::Parsed::Handshake(long) => {
                    if let Some(key) = input.connection.handshake.keys.handshake() {
                        let next = conn::Epoch::Handshake
                            .bind(&input.connection.receive.packet_numbers.spaces)
                            .expected_pn();
                        let open = match key.decrypt(long, next) {
                            Ok(open) => open,
                            Err(error) => return input.reject(error),
                        };
                        if !input.connection.egress.activity.peer_address_validated {
                            input.connection.egress.activity.peer_address_validated = true;
                            input
                                .context
                                .record(conn::Effects::from_bits(conn::Effects::TRANSMIT));
                        }
                        policy.try_process(input, bodies::Packet::long(open, now), sink)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn reset(input: &mut ingress::Input<'_, DOMAIN, B, RECONCILE, D>, wire: &[u8]) -> Reset {
        let Some(token) = reset::Token::from_tail(wire) else {
            return Reset::Absent;
        };
        match input.connection.reset(None, token) {
            machine::Reset::Accept => {
                input
                    .context
                    .record(conn::Effects::from_bits(conn::Effects::LIFECYCLE));
                Reset::Received
            }
            machine::Reset::Ignore => Reset::Absent,
        }
    }

    /// Detects reset only on the cold edge after short-header processing fails.
    fn short_fail(
        input: &mut ingress::Input<'_, DOMAIN, B, RECONCILE, D>,
        wire: &[u8],
        error: conn::Error,
    ) -> Result<(), conn::Error> {
        if matches!(error, conn::Error::Timing(_)) {
            return input.reject(error);
        }
        match Self::reset(input, wire) {
            Reset::Received => Ok(()),
            Reset::Absent => input.reject(error),
        }
    }
}
