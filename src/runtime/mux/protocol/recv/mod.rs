mod events;
mod inputs;

use crate::runtime::mux::handler::hook::{
    data::release,
    set,
    wire::{cert, packet},
};

use std::{net, time};

use dope::runtime;
use runtime::civil;

use crate::{
    conn, errors,
    proto::epoch,
    runtime::{brand, mux},
    stream,
    wire::packet::version,
};
use inputs::Input;
use mux::{app, auth, handler, output, protocol, router};
use router::routing;
use routing::issuer::Source as _;

pub(in crate::runtime) trait Recv<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
>
{
    fn recv_input<I, S>(
        &mut self,
        from: net::SocketAddr,
        input: I,
        keep: I::Retain,
        now: time::Instant,
        epoch: epoch::Sample<S>,
    ) -> Result<(), errors::Receive>
    where
        I: Input<DOMAIN, B, A>,
        S: civil::Source;
}

impl<'a, 'tls, H, const DOMAIN: u8, B, A> Recv<A, H, DOMAIN, B>
    for protocol::Io<'a, 'tls, H, DOMAIN, B, A>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity> + cert::Sink<DOMAIN, A::Identity>,
    B: stream::Recv,
{
    fn recv_input<I, S>(
        &mut self,
        from: net::SocketAddr,
        input: I,
        keep: I::Retain,
        now: time::Instant,
        epoch: epoch::Sample<S>,
    ) -> Result<(), errors::Receive>
    where
        I: Input<DOMAIN, B, A>,
        S: civil::Source,
    {
        let mut mux = router::Turn::new(self.mux.as_mut());
        if mux.lifecycle.shutting_down {
            return Ok(());
        }
        if mux.server.is_some()
            && let Some(req) = version::Unsupported::decode(input.as_ref())
        {
            let len = req.encoded_len();
            if len <= input.as_ref().len() {
                let emission =
                    mux.outgoing
                        .emit_owned(len, len, |out| match req.encode(out, 0xc0) {
                            Ok(packet) => Ok(output::Flight::plain(from, packet)),
                            Err((packet, error)) => Err((packet, Some(error))),
                        });
                if let output::Emission::Allocation {
                    error,
                    requested: need,
                } = emission
                {
                    return Err(errors::Receive::Allocation {
                        error,
                        requested: need,
                    });
                }
            }
            return Ok(());
        }
        mux.route(
            from,
            input,
            now,
            epoch,
            |local, mut sink, slots, key, binding, work, input| {
                let handle = slots.handle(binding.domain, key);
                let scope = local.brand();
                if let Ok(vn) = version::Negotiation::decode(input.as_ref()) {
                    router::State::<A, H::Connection, DOMAIN, B>::trusted_in::<_, false>(
                        scope.reborrow(),
                        slots,
                        key,
                        binding,
                        now,
                        |mut slot| {
                            if slot.conn.routing().is_rejected(&vn) {
                                slot.conn.events().mark(conn::Effects::LIFECYCLE);
                            }
                        },
                    );
                    return Ok(());
                }
                let wire_len = input.as_ref().len();
                let received = {
                    let mut entry = slots.entry(key);
                    let mut slot = entry.access::<false>(scope.reborrow());
                    let token = if slot.conn.routing().is_new(from) {
                        binding.issuer.challenge()
                    } else {
                        None
                    };
                    slot.conn.routing().begin(from, wire_len, token);
                    let (result, dirty) = {
                        let mut ready = app::Readiness::Preserve;
                        let mut events = events::Events::<_, <<H::Events as set::Dispatch<H, DOMAIN, B, A::Send, A::Identity>>::Release as release::Mode<H, DOMAIN, B, A::Send, A::Identity>>::Evidence>::new(|event| match event {
                        events::Event::Diagnostic(detail) => {
                            <<H::Events as set::Dispatch<H, DOMAIN, B, A::Send, A::Identity>>::Packet as packet::Mode<H, DOMAIN, B, A::Send, A::Identity>>::observe(|| {
                                packet::Event::new(sink.as_mut(), from, packet::Failure::Diagnostic(detail), wire_len)
                            });
                        }
                        events::Event::Certificate(failure) => H::certificate(cert::Event::new(
                            sink.as_mut(), handle, from, failure,
                        )),
                        events::Event::Release { proof, source, cause } => {
                            ready.update(<<H::Events as set::Dispatch<H, DOMAIN, B, A::Send, A::Identity>>::Release as release::Mode<H, DOMAIN, B, A::Send, A::Identity>>::release(
                                sink.as_mut(), handle, proof, source, cause,
                            ));
                        }
                    });
                        let (result, mut dirty) = input
                            .receive(
                                keep,
                                slot.conn.reborrow::<true>(),
                                work,
                                brand::Branded::new(scope.reborrow(), *local.value()),
                                now,
                                &mut events,
                            )
                            .into_parts();
                        if let Some(value) = ready.into_ready() {
                            dirty.set_ready(value);
                        }
                        (result.map_err(errors::Receive::Packet), dirty)
                    };
                    slot.conn.events().merge(dirty);
                    slot.conn.routing().end_datagram();
                    result
                };
                router::State::<A, H::Connection, DOMAIN, B>::reconcile(scope, slots, key, binding, now, None);
                received
            },
        )
    }
}
