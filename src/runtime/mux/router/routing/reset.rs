use crate::runtime::brand;
use o3::buffer::{storage, write::Sink as _};

use std::{net, num::NonZero, time};

use crate::runtime::routing::registry;
use crate::{conn, errors, runtime::mux, stream};
use conn::{machine, wire};
use issuer::Source as _;
use mux::{auth, output, router};
use path::reset;
use router::routing;
use routing::{issuer, packets};
use wire::path;

pub(in crate::runtime::mux) fn receive<
    A: auth::Mode<DOMAIN>,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
>(
    state: &mut router::State<A, C, DOMAIN, B>,
    from: net::SocketAddr,
    packet: &[u8],
    now: time::Instant,
) -> Result<(), errors::Receive> {
    let trigger = packets::Header::new(packet);
    if !trigger.is_short() {
        return Ok(());
    }
    if let Some(token) = reset::Token::from_tail(packet) {
        let matched = brand::Token::with(|scope| {
            registry::Scope::with(&mut state.registry, |mut slots| {
                let (entries, side, reset) = slots.resets();
                let mut matched = false;
                for (key, value) in side.bucket(reset.hash(&token)) {
                    if !value.matches(token) {
                        continue;
                    }
                    let Some(key) = entries.admit(key) else {
                        break;
                    };
                    let mut slot = entries.access::<false>(key, scope.reborrow());
                    let accepted = match slot.conn.routing().reset(from, token) {
                        machine::Reset::Ignore => false,
                        machine::Reset::Accept => {
                            slot.conn.events().mark(conn::Effects::LIFECYCLE);
                            true
                        }
                    };
                    if accepted {
                        let (timer, entry) = entries.select(key);
                        registry::Set::refresh(timer, entry, now, conn::DeadlineMode::Exact, None);
                        matched = true;
                    }
                }
                matched
            })
        });
        if matched {
            return Ok(());
        }
    }
    let Some(cfg) = state.server.as_ref().map(A::config) else {
        return Ok(());
    };
    let cfg = cfg.0;
    let Some(secret) = cfg.security.stateless_reset_secret.as_ref() else {
        return Ok(());
    };
    let Some(dcid) = trigger.dcid::<A::LocalRoute>() else {
        return Ok(());
    };
    if trigger.len() < 23 {
        return Ok(());
    }
    let Some(amp) = trigger.len().checked_mul(3) else {
        return Ok(());
    };
    let limit = cfg.packet_max().min(state.outgoing.bytes_capacity).min(amp);
    if limit < 22 {
        return Ok(());
    }
    let len = NonZero::<usize>::MIN.saturating_add((trigger.len() - 1).min(limit) - 1);
    let prefix = NonZero::<usize>::MIN.saturating_add(len.get() - reset::Token::LEN - 1);
    let (outgoing, issuer) = (&mut state.outgoing, &mut state.binding.issuer);
    let emission = outgoing.emit_owned(len.get(), len.get(), |reset| {
        let mut reset = match storage::NonEmpty::try_resize(reset, prefix, 0) {
            Ok(reset) => reset,
            Err(rejected) => {
                let (reset, error) = rejected.into_parts();
                return Err((reset, Some(error)));
            }
        };
        if let Err(issuer::Exhausted::Exhausted) = issuer.reset(&mut reset) {
            return Err((reset.into_storage(), None));
        }
        let first = reset.first_mut();
        *first = (*first & 0x3f) | 0x40;
        if let Err(error) = reset.append().write_slice(&secret.token_for(dcid)) {
            return Err((reset.into_storage(), Some(error)));
        }
        Ok(output::Flight::plain(from, reset))
    });
    match emission {
        output::Emission::Allocation {
            error,
            requested: need,
        } => Err(errors::Receive::Allocation {
            error,
            requested: need,
        }),
        output::Emission::Sent | output::Emission::Skipped => Ok(()),
    }
}
