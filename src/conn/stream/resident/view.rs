use std::mem;

use o3::buffer::{self, resident::Shared};

use crate::conn;
use crate::conn::stream::resident::{Foreign, Handle, Key, Local, Origin, Owner};
use crate::runtime::brand;
use crate::stream;
use crate::wire::stream::Id;

/// Immutable resident registry access branded to one connection scope.
#[repr(transparent)]
pub struct View<'access, 'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    connection: &'access conn::Machine<DOMAIN, B, D>,
    brand: brand::Token<'conn>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    View<'_, 'conn, DOMAIN, B, D>
{
    pub(in crate::conn) fn new<'access>(
        state: &'access conn::Machine<DOMAIN, B, D>,
        brand: brand::Token<'conn>,
    ) -> View<'access, 'conn, DOMAIN, B, D> {
        View {
            connection: state,
            brand,
        }
    }

    /// Stable identity retained once by an upper protocol spanning lexical scopes.
    pub fn origin(&self) -> Origin {
        self.connection.streams.state.receive.map.meta().origin()
    }

    /// Resolves one wire identity into its resident generational key.
    pub fn key(&self, id: Id) -> Option<Key> {
        self.connection.streams.state.resident.read().key(id)
    }

    /// Resolves one wire identity into branded resident auth.
    pub fn handle(&self, id: Id) -> Option<Handle<'conn>> {
        let key = self.key(id)?;
        Some(Handle::new(Local::new(id, key)))
    }

    /// Resolves a generation-checked resident key into branded auth without hashing.
    pub fn handle_key(&self, key: Key) -> Option<Handle<'conn>> {
        let id = self.id(key)?;
        Some(Handle::new(Local::new(id, key)))
    }

    /// Resolves a generation-checked resident key without hashing.
    pub fn id(&self, key: Key) -> Option<Id> {
        self.connection.streams.state.resident.read().id(key)
    }

    /// Validates one retained connection origin for this lexical access.
    pub fn owner(&self, origin: Origin) -> Result<Owner<'conn>, Foreign> {
        if origin != self.origin() {
            return Err(Foreign::new(self.origin(), origin));
        }
        Ok(Owner::new(self.brand))
    }

    /// Recovers branded auth by direct generation lookup without hashing.
    pub fn bind(&self, owner: Owner<'conn>, local: Local) -> Result<Handle<'conn>, super::Stale> {
        self.connection
            .streams
            .state
            .resident
            .read()
            .try_id(local)?;
        Ok(owner.handle(local))
    }
}

const _: () = {
    assert!(
        mem::size_of::<View<'_, '_, 0, Vec<u8>, Shared<'_>>>()
            == mem::size_of::<&conn::Machine<0, Vec<u8>, Shared<'_>>>()
    );
};
