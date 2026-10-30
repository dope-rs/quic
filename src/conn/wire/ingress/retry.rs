use o3::buffer;
use std::{mem, time};

use crate::{
    conn,
    security::qkdf,
    stream,
    wire::{packet::long::retry, stream::Initiator},
};
use conn::{
    output::{
        recovery::{epochs, timer},
        transmit,
    },
    wire::ingress,
};
use transmit::builder;

pub(super) struct Retry<
    'a,
    'driver,
    const DOMAIN: u8,
    B: stream::Recv,
    const RECONCILE: bool,
    D: buffer::raw::Segment,
> {
    input: &'a mut ingress::Input<'driver, DOMAIN, B, RECONCILE, D>,
}

impl<'a, 'driver, const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Retry<'a, 'driver, DOMAIN, B, RECONCILE, D>
{
    pub(super) const fn new(
        input: &'a mut ingress::Input<'driver, DOMAIN, B, RECONCILE, D>,
    ) -> Self {
        Self { input }
    }

    pub(super) fn receive(self, wire: &[u8], now: time::Instant) -> Result<(), conn::Error> {
        use builder::crypto::Room;

        let input = self.input;
        if !matches!(input.connection.peer.local, Initiator::Client)
            || input.connection.control.probe().is_retry()
        {
            return Ok(());
        }
        if !input.connection.handshake.keys.long.can_retry()
            || input.connection.path.origin.peer_first_scid.is_some()
        {
            return Ok(());
        }
        let retry = retry::Ref::decode(wire).map_err(conn::Error::Long)?;
        let odcid = input.connection.path.origin.original_dcid;
        let local = input.connection.path.local.id();
        let mut buf = mem::take(&mut input.connection.scratch.header);
        buf.clear();
        let (peer, size) = {
            let check = match retry.verify_into(odcid.as_ref_id(), local.as_ref_id(), &mut buf) {
                Ok(check) => check,
                Err(error) => {
                    buf.clear();
                    input.connection.scratch.header = buf;
                    return Err(conn::Error::Retry(error));
                }
            };
            let Some(valid) = check else {
                buf.clear();
                input.connection.scratch.header = buf;
                return Ok(());
            };
            let peer = valid.scid().into_owned();
            input.connection.path.peer.validate_id(peer.as_ref_id())?;
            (peer, valid.token().len())
        };
        input.connection.scratch.header = input.connection.path.origin.retry(buf);
        let pmtu = input.connection.egress.cc.metrics().current_mtu() as usize;
        let limit = input.connection.egress.cc.metrics().ceiling().min(pmtu);
        let Some(number) = conn::Epoch::Initial
            .bind_mut(&mut input.connection.egress.recovery.spaces)
            .next()
        else {
            input.connection.egress.lifecycle.state = conn::State::Closed;
            input
                .context
                .record(conn::Effects::from_bits(conn::Effects::LIFECYCLE));
            return Ok(());
        };
        let plain = builder::Builder::<'_, DOMAIN, B, D>::initial_for(
            peer.len(),
            local.len(),
            size,
            limit,
            number.encoded_len(),
        );
        let crypto = input
            .connection
            .handshake
            .crypto
            .bytes(conn::Epoch::Initial)
            .len();
        if limit < conn::MIN_INITIAL_LEN || crypto == 0 || Room::new(plain).limit(0) == 0 {
            input.connection.egress.lifecycle.state = conn::State::Closed;
            input
                .context
                .record(conn::Effects::from_bits(conn::Effects::LIFECYCLE));
            return Err(conn::Error::PacketCeiling);
        }
        let secret = qkdf::Initial::try_new(peer.as_slice())?;
        epochs::Epochs::new(input.connection).retry();
        let keys = qkdf::Pair::try_client(secret)?;
        input
            .connection
            .handshake
            .keys
            .long
            .replace(keys.peer, keys.local);
        input.connection.path.origin.retry_source_cid = Some(peer);
        input.connection.path.peer.set_id(peer)?;
        input.connection.control.queue().retry();
        input.connection.egress.lifecycle.sent_initial = false;
        input
            .context
            .record(conn::Effects::from_bits(conn::Effects::SCHEDULER));
        timer::Timer::try_update(
            &mut input.connection.egress,
            &input.connection.handshake.keys,
            input.connection.peer.local,
            now,
        )
        .or_else(|error| input.reject(error.into()))
    }
}

const _: () = assert!(usize::BITS >= u64::BITS);
