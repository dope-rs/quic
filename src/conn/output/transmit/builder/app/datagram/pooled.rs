use crate::conn::output::recovery::timer;
use crate::conn::output::transmit::builder::ack;
use crate::conn::stream::state::transmit::log::journal;
use o3::buffer;
use std::{num::NonZero, time};

use crate::conn::output::transmit::packet::plan::Plan;
use crate::conn::output::transmit::{
    self, Policy,
    builder::{self, app::datagram::Outcome},
    permit,
};
use crate::proto::datagram;
use crate::stream;
use crate::wire::packet::{kind, short};
use crate::{conn, security::crypto};

/// Retains the admitted header and tracking state through an exclusive connection borrow.
pub(in crate::conn::output::transmit) struct Pooled<
    'connection,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
> {
    connection: &'connection mut conn::Machine<DOMAIN, B, D>,
    admitted: permit::Admitted,
}

impl<'connection, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Pooled<'connection, DOMAIN, B, D>
{
    pub(in crate::conn::output::transmit) fn try_new(
        conn: &'connection mut conn::Machine<DOMAIN, B, D>,
        now: time::Instant,
        max: NonZero<usize>,
    ) -> Result<Self, &'connection mut conn::Machine<DOMAIN, B, D>> {
        let Some(permit::Pooled::Ready(admitted)) = permit::Permit::new(conn).pooled(now, max)
        else {
            return Err(conn);
        };
        Ok(Self {
            connection: conn,
            admitted,
        })
    }

    pub(in crate::conn::output::transmit) fn build<'pool, 'records>(
        self,
        now: time::Instant,
        packet: datagram::Packet<'pool>,
        target: &'records Policy,
        records: &'records mut builder::Records,
        pto: Option<(time::Duration, time::Duration)>,
    ) -> Outcome<'pool, 'records, DOMAIN, B, D>
    where
        'connection: 'records,
    {
        let (phase, number, max) = self.admitted.into_parts();
        let builder = builder::Builder::new(self.connection, target, records);
        let max = max.get();
        let limit = max
            .saturating_sub(conn::TAG_LEN)
            .saturating_sub(1)
            .saturating_sub(packet.len());

        let prefix = &mut builder.connection.scratch.frames;
        let dcid = *builder.connection.path.peer.id();
        let needed = 1 + dcid.len() + usize::from(number.encoded_len());
        let mut encoded =
            match short::Ref::new(dcid.as_ref_id(), number.encoding(), phase).prefix(prefix) {
                Ok(encoded) => encoded,
                Err(error) => {
                    prefix.clear();
                    return Outcome::Admission(
                        packet,
                        transmit::Admission::Payload {
                            error,
                            requested: needed,
                        },
                    );
                }
            };
        let ack = match ack::append::<kind::OneRtt, false>(
            &builder.connection.receive.packet_numbers,
            now,
            &mut encoded,
            limit,
        ) {
            Ok(ack) => ack,
            Err(error) => {
                prefix.clear();
                return Outcome::Admission(packet, error);
            }
        };

        use crypto::output::Prepared;
        let packet = match Prepared::try_new(packet, max, encoded) {
            Ok(packet) => packet,
            Err((packet, error)) => {
                return Outcome::Admission(packet, error);
            }
        };
        prefix.clear();
        let mut commit = Plan::new(conn::Epoch::Application, number);
        commit.flags.ack = ack;
        commit.flags.set_elicit(true);
        commit.flags.set_flight(true);
        commit.flags.set_datagram(true);
        let Some(target) = builder.target(commit.path.route) else {
            return Outcome::Rejected(packet.reject());
        };
        use builder::pending;

        let prepared = match pending::Packet::try_new(
            journal::Schedule::new(builder).finish(),
            commit,
            target,
        ) {
            Ok(prepared) => prepared,
            Err((_, error)) => {
                return Outcome::Admission(packet.reject(), error);
            }
        };
        let timer = match timer::Timer::new(prepared.conn()).try_datagram(now, pto) {
            Ok(timer) => timer,
            Err(error) => {
                prepared.reject();
                return Outcome::Admission(packet.reject(), error.into());
            }
        };
        match prepared.protect(packet) {
            Ok((packet, prepared)) => Outcome::Sealed(packet, prepared, timer),
            Err(failure) => match failure.into_retry() {
                Ok((failed, _, error)) => match error {
                    Some(error) => Outcome::Admission(failed.reject(), error),
                    None => Outcome::Rejected(failed.reject()),
                },
                Err(failed) => Outcome::Crypto(failed.into_error()),
            },
        }
    }
}
