use std::marker;

use crate::conn::output::control::owner;
use crate::{errors::Code, wire::varint::VarInt};

const DEFERRED: u64 = 1 << 62;
const LIVE: u64 = 1 << 63;
const STATE: u64 = DEFERRED | LIVE;

#[repr(transparent)]
pub(in crate::conn) struct Signal<Kind>(u64, marker::PhantomData<fn() -> Kind>);

impl<Kind> Signal<Kind> {
    pub(in crate::conn) const fn new() -> Self {
        Self(0, marker::PhantomData)
    }

    pub(in crate::conn) const fn is_deferred(&self) -> bool {
        self.0 & STATE == DEFERRED
    }

    pub(in crate::conn) const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub(in crate::conn) fn deferred(&mut self) -> Option<owner::Deferred<'_, Kind>> {
        if !self.is_deferred() {
            return None;
        }
        let value = self.0 & Code::MAX_VALUE;
        Some(owner::Deferred {
            signal: self,
            code: Code::from_varint(VarInt::saturate(value as u128)),
        })
    }

    pub(in crate::conn::output::control) fn defer(&mut self, value: Code) {
        self.0 = DEFERRED | value.get();
    }

    pub(in crate::conn::output::control) fn owner(&self) -> Option<owner::Key<Kind>> {
        if self.0 & LIVE == 0 {
            None
        } else {
            owner::Key::from_raw(self.0 & !LIVE)
        }
    }

    pub(in crate::conn::output::control::owner) fn set_owner(&mut self, owner: owner::Key<Kind>) {
        self.0 = LIVE | owner.into_raw();
    }

    pub(in crate::conn::output::control) fn clear(&mut self) {
        self.0 = 0;
    }
}
