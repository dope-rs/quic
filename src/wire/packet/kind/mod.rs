mod boundary;

use o3::base::num::bounded;

pub(crate) use boundary::Boundary;

/// Initial packet provenance.
pub struct Initial;

/// Handshake packet provenance.
pub struct Handshake;

/// Zero-RTT packet provenance.
pub struct ZeroRtt;

/// One-RTT packet provenance.
pub struct OneRtt;

/// A sealed QUIC packet kind.
pub trait Kind: Boundary {}

impl Kind for Initial {}

impl Kind for Handshake {}

impl Kind for ZeroRtt {}

impl Kind for OneRtt {}

pub trait Long: Kind {
    #[doc(hidden)]
    const TYPE: u8;
    #[doc(hidden)]
    const MIN_LENGTH_WIDTH: bounded::NonZeroU32<1, 2> = bounded::NonZeroU32::exact::<1>();
}

impl Long for Initial {
    const TYPE: u8 = super::LONG_INITIAL;
    /// Keep 1200-byte padding exact across the one-byte Length boundary.
    const MIN_LENGTH_WIDTH: bounded::NonZeroU32<1, 2> = bounded::NonZeroU32::exact::<2>();
}

impl Long for Handshake {
    const TYPE: u8 = super::LONG_HANDSHAKE;
}

impl Long for ZeroRtt {
    const TYPE: u8 = super::LONG_ZERO_RTT;
}
