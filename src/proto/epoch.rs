//! Lazy civil epoch auth for QUIC token admission.

use std::mem;

use dope::runtime::civil;
use o3::base::time;

use crate::runtime::brand;

/// Lazy, linear epoch-clock auth for one receive operation.
#[must_use]
#[repr(transparent)]
pub struct Sample<S>(S);

impl<S> Sample<S> {
    pub const fn new(source: S) -> Self {
        Self(source)
    }
}

impl<S: civil::Source> Sample<S> {
    pub(crate) fn observe<'scope>(
        self,
        brand: brand::Token<'scope>,
    ) -> Result<Observed<'scope>, civil::Error> {
        civil::Source::read(&self.0).map(|value| Observed(brand::Branded::new(brand, value)))
    }
}

/// Unobserved production wall-clock auth.
pub const WALL_CLOCK: Sample<civil::System> = Sample::new(civil::System::NEW);

/// Epoch auth branded to the admission txn that observed it.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct Observed<'scope>(brand::Branded<'scope, time::Unix<time::Nanos>>);

impl<'scope> Observed<'scope> {
    pub(crate) const fn unix_seconds(&self) -> u64 {
        self.0.value().floor_secs().ticks()
    }

    pub(crate) fn expire(
        &self,
        lifetime: time::Positive,
    ) -> Result<TokenExpiry<'scope>, time::Add> {
        let value = self.0.value().try_add(lifetime.get())?;
        Ok(TokenExpiry(brand::Branded::new(self.0.brand(), value)))
    }
}

/// A checked expiry derived from an observation in the same admission scope.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct TokenExpiry<'scope>(brand::Branded<'scope, time::Unix<time::Nanos>>);

impl TokenExpiry<'_> {
    pub(crate) const fn unix_seconds(&self) -> u64 {
        self.0.value().floor_secs().ticks()
    }
}

const _: () = {
    assert!(mem::size_of::<Sample<civil::System>>() == 0);
    assert!(!mem::needs_drop::<Sample<civil::System>>());
    assert!(mem::size_of::<time::Unix<time::Nanos>>() == mem::size_of::<u64>());
    assert!(mem::align_of::<time::Unix<time::Nanos>>() == mem::align_of::<u64>());
    assert!(mem::size_of::<Observed<'static>>() == mem::size_of::<u64>());
    assert!(mem::align_of::<Observed<'static>>() == mem::align_of::<u64>());
    assert!(mem::size_of::<TokenExpiry<'static>>() == mem::size_of::<u64>());
    assert!(mem::align_of::<TokenExpiry<'static>>() == mem::align_of::<u64>());
};
