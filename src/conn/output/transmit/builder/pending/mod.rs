use crate::{
    conn::{
        self,
        output::{
            self,
            control::encode,
            transmit::{
                self,
                packet::{plan::Plan, seals},
            },
        },
        stream::state::transmit::log::journal::{self, Entry},
        wire::crypto::tx,
    },
    proto::recovery::numbers,
    security::crypto::{self, op},
    stream,
};
use draft::Draft;
use o3::buffer::{self, resident};
use std::{mem, time};

mod draft;
mod records;
mod selected;

pub(in crate::conn) use records::{Input, Preparation};

pub(in crate::conn::output::transmit) enum Failure<P, R, C> {
    Retry(P, R),
    Admission(P, R, transmit::Admission<crypto::Dimensions>),
    Crypto(C),
}

impl<P, R, C> Failure<P, R, C> {
    pub(in crate::conn::output::transmit) fn release(self) -> Failure<(), R, C> {
        match self {
            Self::Retry(seal, pending) => {
                drop(seal);
                Failure::Retry((), pending)
            }
            Self::Admission(seal, pending, error) => {
                drop(seal);
                Failure::Admission((), pending, error)
            }
            Self::Crypto(failed) => Failure::Crypto(failed),
        }
    }
}

pub(in crate::conn::output::transmit) struct Failed<'a> {
    scratch: &'a mut conn::Scratch,
    error: crypto::Error,
}

#[must_use]
/// Holds connection auth for one admitted packet plan.
/// `N` tracks packet-number auth: failure changes nothing; successful
/// protection consumes one number and exposes [`Self::commit`].
pub(in crate::conn::output::transmit) struct Packet<
    'a,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    N = op::Protected<numbers::Sealing>,
    A = output::AmpSent,
> {
    builder: tx::Prepared<Draft<'a, DOMAIN, B, D>>,
    plan: Plan<N>,
    amp: A,
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, N, A>
    Packet<'a, DOMAIN, B, D, N, A>
{
    pub(in crate::conn::output::transmit) const fn plan(&self) -> &Plan<N> {
        &self.plan
    }

    pub(in crate::conn::output::transmit) fn controls(&self) -> &[encode::Written] {
        self.builder.owner().controls()
    }

    pub(in crate::conn::output::transmit) fn streams(&self) -> &[Entry] {
        self.builder.owner().streams()
    }

    pub(in crate::conn::output::transmit) fn has_crypto(&self) -> bool {
        !self.builder.is_empty()
    }

    pub(in crate::conn::output::transmit) fn conn(&self) -> &conn::Machine<DOMAIN, B, D> {
        self.builder.owner().conn()
    }

    pub(in crate::conn::output::transmit) fn scratch(&mut self) -> &mut conn::Scratch {
        self.builder.context().scratch
    }
}

impl Failed<'_> {
    pub(in crate::conn::output::transmit) fn scratch(&mut self) -> &mut conn::Scratch {
        self.scratch
    }

    pub(in crate::conn::output::transmit) fn into_error(self) -> crypto::Error {
        self.error
    }
}

impl<'a, P> Failure<P, &'a mut conn::Scratch, Failed<'a>> {
    pub(in crate::conn::output::transmit) fn scratch(&mut self) -> &mut conn::Scratch {
        match self {
            Self::Retry(_, scratch) | Self::Admission(_, scratch, _) => scratch,
            Self::Crypto(failed) => failed.scratch(),
        }
    }

    pub(in crate::conn::output::transmit) fn into_retry(
        self,
    ) -> Result<
        (
            P,
            &'a mut conn::Scratch,
            Option<transmit::Admission<crypto::Dimensions>>,
        ),
        Failed<'a>,
    > {
        match self {
            Self::Retry(seal, pending) => Ok((seal, pending, None)),
            Self::Admission(seal, pending, error) => Ok((seal, pending, Some(error))),
            Self::Crypto(failed) => Err(failed),
        }
    }

    pub(in crate::conn::output::transmit) fn into_error(self) -> Option<transmit::Admission> {
        match self {
            Self::Retry(..) => None,
            Self::Admission(_, _, error) => Some(error.into_error()),
            Self::Crypto(failed) => Some(transmit::Admission::Protection(failed.into_error())),
        }
    }
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Packet<'a, DOMAIN, B, D, numbers::Packet, ()>
{
    pub(in crate::conn::output::transmit) fn reject(self) -> &'a mut conn::Scratch {
        self.builder.cancel().cancel()
    }

    pub(in crate::conn::output::transmit::builder) fn try_new(
        input: journal::Ready<records::Input<'a, DOMAIN, B, D>>,
        mut plan: Plan<numbers::Packet>,
        target: transmit::Destination,
    ) -> Result<
        Self,
        (
            &'a mut conn::Scratch,
            transmit::Admission<crypto::Dimensions>,
        ),
    > {
        use crate::conn::output::journals;
        use crate::conn::stream::state::transmit::log::journal;
        use o3::depot::capacity::Reason;
        use records::Records;

        let tracked = plan.flags.is_in_flight()
            || !input.owner().controls.is_empty()
            || !input.owner().streams.is_empty()
            || plan.flags.is_early()
            || input.owner().crypto.is_some()
            || plan.path.pmtud_probe.is_some();
        let (records, crypto) = if tracked {
            let mut input = match journal::Reserve::try_new(input) {
                Ok(input) => input,
                Err((input, error)) => {
                    let error = match error {
                        journal::ReserveError::Capacity { reason, records } => {
                            transmit::Admission::Stream { records, reason }
                        }
                        journal::ReserveError::Credit {
                            sent,
                            additional: add,
                        } => transmit::Admission::StreamCredit {
                            sent,
                            additional: add,
                        },
                    };
                    return Err((input.into_scratch(), error));
                }
            };
            let crypto = input.take_crypto();
            let epoch = plan.epoch;
            let number = plan.packet_number.protected();
            match journals::Reserve::try_new(records::Tracked::new(input), epoch, number) {
                Ok(reserved) => (Records::Tracked(reserved), crypto),
                Err((input, reason, demand)) => {
                    let (controls, streams) = demand.counts();
                    let input = input.cancel();
                    *input.crypto = crypto;
                    return Err((
                        input.into_scratch(),
                        transmit::Admission::Packet {
                            space: epoch,
                            number,
                            controls,
                            streams,
                            reason,
                        },
                    ));
                }
            }
        } else {
            (Records::Untracked(input.cancel()), None)
        };
        plan.set_tracked(tracked);
        let draft = Draft {
            records,
            destination: target,
            crypto,
        };
        match tx::Prepared::try_new(draft) {
            Ok(builder) => Ok(Self {
                builder,
                plan,
                amp: (),
            }),
            Err(draft) => {
                let input = draft.records.cancel();
                *input.crypto = draft.crypto;
                Err((
                    input.into_scratch(),
                    transmit::Admission::Crypto {
                        needed: 1,
                        reason: Reason::Full,
                    },
                ))
            }
        }
    }

    pub(in crate::conn::output::transmit) fn protect<P>(
        self,
        seal: P,
    ) -> transmit::Protected<'a, DOMAIN, B, D, P, P::Output>
    where
        P: seals::Seal<DOMAIN>,
    {
        let bytes = seal.wire_len();
        let Some(amp) = self.conn().egress.activity.plan_amp(bytes) else {
            return Err(Failure::Admission(
                seal,
                self.builder.cancel().cancel(),
                transmit::Admission::Amplification { bytes },
            ));
        };
        let Self {
            mut builder,
            plan,
            amp: (),
        } = self;
        let epoch = plan.epoch;
        let context = builder.context();
        let (output, plan) =
            match seals::packet(context.keys, epoch.bind_mut(context.spaces), seal, plan) {
                Ok(output) => output,
                Err(seals::Failure::Retry(seal, _)) => {
                    return Err(Failure::Retry(seal, builder.cancel().cancel()));
                }
                Err(seals::Failure::Crypto(error)) => {
                    return Err(Failure::Crypto(Failed {
                        scratch: builder.cancel().cancel(),
                        error,
                    }));
                }
            };
        Ok((output, Packet { builder, plan, amp }))
    }
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Packet<'a, DOMAIN, B, D> {
    pub(in crate::conn::output::transmit) fn destination(&self) -> transmit::Destination {
        self.builder.owner().destination()
    }

    pub(in crate::conn::output::transmit) fn commit(self, now: time::Instant) {
        let Self { builder, plan, amp } = self;
        let (records, crypto) = builder.commit();
        records.commit(plan, crypto, amp, now);
    }
}

const _: () = {
    assert!(
        mem::size_of::<Failed<'static>>()
            == mem::size_of::<crypto::Error>() + mem::size_of::<usize>()
    );
    assert!(mem::size_of::<Option<Failed<'static>>>() == mem::size_of::<Failed<'static>>());
    assert!(
        mem::size_of::<Packet<'static, 0, Vec<u8>, resident::Shared<'static>, numbers::Packet, ()>>(
        ) + mem::size_of::<output::AmpSent>()
            == mem::size_of::<Packet<'static, 0, Vec<u8>, resident::Shared<'static>>>()
    );
    assert!(
        mem::size_of::<
            Result<
                Packet<'static, 0, Vec<u8>, resident::Shared<'static>, numbers::Packet, ()>,
                transmit::Admission<crypto::Dimensions>,
            >,
        >() == mem::size_of::<
            Packet<'static, 0, Vec<u8>, resident::Shared<'static>, numbers::Packet, ()>,
        >()
    );
    assert!(!mem::needs_drop::<
        Packet<'static, 0, Vec<u8>, resident::Shared<'static>>,
    >());
};
