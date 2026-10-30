use crate::conn;
use crate::conn::life::options::builder;
use capacity::Role as _;
use conn::machine::storage;
use storage::capacity;

pub struct Journals {
    packet: capacity::Capacity<capacity::Packet>,
    crypto: capacity::Capacity<capacity::Crypto>,
    control: capacity::Capacity<capacity::Control>,
    stream: capacity::Capacity<capacity::Stream>,
}

impl Journals {
    pub fn packet<const N: usize>(mut self) -> Self {
        self.packet = capacity::Capacity::constant::<N>();
        self
    }

    pub fn crypto<const N: usize>(mut self) -> Self {
        self.crypto = capacity::Capacity::constant::<N>();
        self
    }

    pub fn control<const N: usize>(mut self) -> Self {
        self.control = capacity::Capacity::constant::<N>();
        self
    }

    pub fn stream<const N: usize>(mut self) -> Self {
        self.stream = capacity::Capacity::constant::<N>();
        self
    }

    pub fn try_packet(mut self, actual: usize) -> Result<Self, builder::Invalid> {
        let Some(value) = capacity::Capacity::try_new(actual) else {
            return Err(builder::Invalid::PacketJournal {
                actual,
                minimum: capacity::Packet::MIN.get() as usize,
                maximum: u16::MAX as usize,
            });
        };
        self.packet = value;
        Ok(self)
    }

    pub fn try_crypto(mut self, actual: usize) -> Result<Self, builder::Invalid> {
        let Some(value) = capacity::Capacity::try_new(actual) else {
            return Err(builder::Invalid::CryptoJournal {
                actual,
                minimum: capacity::Crypto::MIN.get() as usize,
                maximum: u16::MAX as usize,
            });
        };
        self.crypto = value;
        Ok(self)
    }

    pub fn try_control(mut self, actual: usize) -> Result<Self, builder::Invalid> {
        let Some(value) = capacity::Capacity::try_new(actual) else {
            return Err(builder::Invalid::ControlJournal {
                actual,
                minimum: capacity::Control::MIN.get() as usize,
                maximum: u16::MAX as usize,
            });
        };
        self.control = value;
        Ok(self)
    }

    pub fn try_stream(mut self, actual: usize) -> Result<Self, builder::Invalid> {
        let Some(value) = capacity::Capacity::try_new(actual) else {
            return Err(builder::Invalid::StreamJournal {
                actual,
                minimum: capacity::Stream::MIN.get() as usize,
                maximum: u16::MAX as usize,
            });
        };
        self.stream = value;
        Ok(self)
    }

    pub(super) fn promote(self) -> capacity::Capacities {
        capacity::Capacities::new(self.packet, self.crypto, self.control, self.stream)
    }

    pub(super) fn from(limits: capacity::Capacities) -> Self {
        Self {
            packet: limits.packet(),
            crypto: limits.crypto(),
            control: limits.control(),
            stream: limits.stream(),
        }
    }
}

impl Default for Journals {
    fn default() -> Self {
        Self::from(capacity::Capacities::default())
    }
}
