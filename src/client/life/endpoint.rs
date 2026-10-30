use o3::depot::heap::indexed::resident;
use std::marker;

use crate::client;
use crate::conn::{id, life};

#[derive(Clone, Copy)]
pub(super) enum Idle<'d, const DOMAIN: u8> {
    Handshaking(id::Handle<id::Driver<'d>, DOMAIN>),
    Dormant,
}

pub(super) struct Types<'d, const DOMAIN: u8>(
    marker::PhantomData<id::Handle<id::Driver<'d>, DOMAIN>>,
);

impl<'d, const DOMAIN: u8> resident::Values for Types<'d, DOMAIN> {
    type Common = Endpoint;
    type Scheduled = ();
    type Idle = Idle<'d, DOMAIN>;
    type Control = client::AttemptId;
    type Data = id::Handle<id::Driver<'d>, DOMAIN>;
    type Active = id::Handle<id::Driver<'d>, DOMAIN>;
}

pub(super) fn handle<'a, 'd, const DOMAIN: u8>(
    value: resident::Borrowed<'a, Types<'d, DOMAIN>>,
) -> Option<id::Handle<id::Driver<'d>, DOMAIN>> {
    match value {
        resident::Value::Idle(Idle::Handshaking(handle))
        | resident::Value::Data(handle)
        | resident::Value::Active(handle) => Some(*handle),
        resident::Value::Scheduled(())
        | resident::Value::Idle(Idle::Dormant)
        | resident::Value::Control(_) => None,
    }
}

pub(super) struct Endpoint {
    pub(super) attempt: client::AttemptState,
    pub(super) reconnect: Option<life::Reconnect>,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            attempt: client::AttemptState::initial(),
            reconnect: None,
        }
    }
}
