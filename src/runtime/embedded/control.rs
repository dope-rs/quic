use std::net;

use dope::core::driver::schedule::clock;
use dope::manifold::app::dispatch;
use o3::buffer::resident;

use crate::conn::id;
use crate::conn::life::{options, tls::clients};
use crate::errors;
use crate::runtime::embedded;
use crate::runtime::embedded::link;
use crate::runtime::mux::app;
use crate::runtime::mux::handler;
use crate::runtime::mux::output;
use crate::runtime::routing;
use crate::stream;
use handler::hook::set;
use handler::hook::wire::cert;
use handler::hook::wire::packet;
use output::quantum::Quantum;

/// Exclusive coordination access to one installed socket-free endpoint.
#[repr(transparent)]
pub struct Control<'step, 'd, const ID: u8, H, B, S>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
{
    endpoint: dispatch::raw::Installed<'step, 'd, embedded::Endpoint<'d, ID, H, B, S>>,
}

impl<'step, 'd, const ID: u8, H, S, const ADAPTIVE: bool>
    Control<'step, 'd, ID, H, stream::RecvBuffer<'d, ADAPTIVE>, S>
where
    H: handler::Handler<ID, stream::RecvBuffer<'d, ADAPTIVE>, resident::Shared<'d>, id::Driver<'d>>,
{
    /// Relays one bounded output turn without copying packet bytes.
    /// A direction-branded link vacancy is reserved before the source queue
    /// releases its owner, so saturation leaves that queue untouched.
    pub fn relay<const ROUTE: u8, const TO: u8, DH, DS, const DESTINATION_ADAPTIVE: bool>(
        &mut self,
        dst: &mut Control<'_, 'd, TO, DH, stream::RecvBuffer<'d, DESTINATION_ADAPTIVE>, DS>,
        link: &mut link::Control<'_, 'd, ROUTE, ID, TO>,
        now: clock::Moment<'d>,
    ) -> Result<usize, embedded::Error<'d, ID, TO>>
    where
        DH: handler::Handler<
                TO,
                stream::RecvBuffer<'d, DESTINATION_ADAPTIVE>,
                resident::Shared<'d>,
                id::Driver<'d>,
            > + cert::Sink<TO, id::Driver<'d>>,
        DH::Events: set::Dispatch<
                DH,
                TO,
                stream::RecvBuffer<'d, DESTINATION_ADAPTIVE>,
                resident::Shared<'d>,
                id::Driver<'d>,
                Packet = packet::Off,
            >,
    {
        let mut source = self.endpoint.as_mut().project();
        source.flush.open();
        if let Some(flight) = link.reclaim() {
            source.mux.as_mut().output().recycle(flight);
        }
        source
            .mux
            .as_mut()
            .output()
            .drive_at(now)
            .map_err(embedded::Error::Source)?;
        let mut quota = Quantum::new();
        loop {
            if source.mux.as_mut().output().is_empty() {
                break;
            }
            let Some(slot) = link.vacancy() else {
                source.flush.block();
                break;
            };
            let Some(credit) = quota.credit() else {
                break;
            };
            let submit = source.mux.as_mut().output().submit(credit, |flight| {
                let mut target = dst.endpoint.as_mut().project();
                slot.try_for_each(flight, |from, packet, keep| {
                    target
                        .mux
                        .as_mut()
                        .observe(now, |mut turn| turn.receive(from, packet, keep))
                })
            });
            let (received, grant) = match submit {
                output::Submit::Accepted(received, grant) => (received, grant),
                output::Submit::Empty | output::Submit::Deferred => {
                    break;
                }
                output::Submit::Rejected(error) => {
                    return Err(match error {
                        link::AdoptError::WrongPeer { actual, expected } => {
                            embedded::Error::WrongPeer {
                                actual,
                                expected: *expected,
                            }
                        }
                        link::AdoptError::TooLarge {
                            resident_bytes: bytes,
                            limit,
                        } => embedded::Error::FlightTooLarge {
                            resident_bytes: bytes,
                            limit,
                        },
                        link::AdoptError::Projection {
                            projected: bytes,
                            resident,
                        } => embedded::Error::Projection {
                            projected: bytes,
                            resident,
                        },
                    });
                }
            };
            if let Some(flight) = link.reclaim() {
                source.mux.as_mut().output().recycle(flight);
            }
            received.map_err(embedded::Error::Receive)?;
            if grant.commit().is_exhausted() {
                break;
            }
        }
        dst.endpoint
            .as_mut()
            .project()
            .mux
            .as_mut()
            .output()
            .drive_at(now)
            .map_err(embedded::Error::Destination)?;
        Ok(quota.packets())
    }
}

impl<'step, 'd, const ID: u8, H, B, S> Control<'step, 'd, ID, H, B, S>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
{
    pub(super) fn new(
        inner: dispatch::raw::Installed<'step, 'd, embedded::Endpoint<'d, ID, H, B, S>>,
    ) -> Self {
        Self { endpoint: inner }
    }

    pub fn handler(&self) -> &H {
        self.endpoint.as_ref().get_ref().handler()
    }

    pub fn len(&self) -> usize {
        self.endpoint.as_ref().get_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn sole(&self) -> Option<id::Handle<id::Driver<'d>, ID>> {
        self.endpoint.as_ref().get_ref().sole()
    }

    pub fn seal(&mut self) {
        self.endpoint.as_mut().project().mux.seal();
    }

    pub fn connect<R: routing::PeerRoute>(
        &mut self,
        now: clock::Moment<'d>,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        opts: options::Options,
        route: R,
    ) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Connect> {
        self.endpoint
            .as_mut()
            .project()
            .mux
            .observe(now, |mut turn| {
                turn.protocol().connect_with(peer, auth, opts, route)
            })
    }

    pub fn try_close(
        &mut self,
        now: clock::Moment<'d>,
        handle: id::Handle<id::Driver<'d>, ID>,
    ) -> Result<(), errors::Access> {
        self.endpoint
            .as_mut()
            .project()
            .mux
            .observe(now, |mut turn| turn.protocol().try_close(handle))
    }

    pub fn with<R>(
        &mut self,
        now: clock::Moment<'d>,
        handle: id::Handle<id::Driver<'d>, ID>,
        op: impl for<'scope> FnOnce(
            app::Connection<'scope, H::Connection, ID, B, resident::Shared<'d>, id::Driver<'d>>,
        ) -> R,
    ) -> Result<R, errors::Access> {
        self.endpoint
            .as_mut()
            .project()
            .mux
            .observe(now, |mut turn| turn.with_app(handle, op))
    }
}
