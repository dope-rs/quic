use std::marker;

use o3::base::marker::ThreadBound;
use rustls::quic;

use crate::{security::crypto, wire};
use crypto::op;
use wire::packet::{self, header, header::Number};

pub(in crate::security::crypto) struct Cipher<O> {
    pub(super) packet: Packet<O>,
    header: Box<dyn quic::HeaderProtectionKey>,
}

/// One admitted packet key with no ownership of the direction's header key.
#[repr(transparent)]
pub(crate) struct Packet<O> {
    packet: Box<dyn quic::PacketKey>,
    marker: marker::PhantomData<fn(O) -> O>,
    bound: ThreadBound,
}

impl<O> Cipher<O> {
    pub(in crate::security::crypto) fn try_new(
        keys: quic::DirectionalKeys,
    ) -> Result<Self, crypto::Dimensions> {
        let sample = keys.header.sample_len();
        let tag = keys.packet.tag_len();
        if sample != header::SAMPLE_LEN || tag != packet::TAG_LEN {
            return Err(crypto::Dimensions { sample, tag });
        }
        Ok(Self {
            packet: Packet::new(keys.packet, ThreadBound::NEW),
            header: keys.header,
        })
    }
}

impl<O> Packet<O> {
    fn new(packet: Box<dyn quic::PacketKey>, bound: ThreadBound) -> Self {
        Self {
            packet,
            marker: marker::PhantomData,
            bound,
        }
    }

    pub(in crate::security::crypto) fn try_next(
        &self,
        packet: Box<dyn quic::PacketKey>,
    ) -> Result<Self, crypto::Dimensions> {
        let tag = packet.tag_len();
        if tag != packet::TAG_LEN {
            return Err(crypto::Dimensions {
                sample: header::SAMPLE_LEN,
                tag,
            });
        }
        Ok(Self::new(packet, self.bound))
    }

    pub(in crate::security::crypto) fn seal_limit(&self) -> u64 {
        self.packet.confidentiality_limit()
    }

    pub(in crate::security::crypto) fn open_limit(&self) -> u64 {
        self.packet.integrity_limit()
    }
}

impl Cipher<op::Seal> {
    /// Packet admission retains a 16-byte sample and a 1..=4-byte number.
    pub(in crate::security::crypto) fn mask(
        &self,
        sample: &[u8; header::SAMPLE_LEN],
        first: &mut u8,
        number: &mut [u8],
    ) -> Result<(), crypto::Error> {
        self.header
            .encrypt_in_place(sample, first, number)
            .map_err(crypto::Error::HeaderEncrypt)
    }

    pub(in crate::security::crypto) fn seal(
        &self,
        number: Number,
        header: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; packet::TAG_LEN], crypto::Error> {
        let tag = self
            .packet
            .packet
            .encrypt_in_place(number.get(), header, body)
            .map_err(crypto::Error::Encrypt)?;
        tag.as_ref()
            .try_into()
            .map_err(|_| crypto::Error::TagDimensions {
                actual: tag.as_ref().len(),
                required: packet::TAG_LEN,
            })
    }
}

impl Cipher<op::Open> {
    /// Key admission retains the sample size; the number extent is fixed here.
    pub(in crate::security::crypto) fn unmask(
        &self,
        sample: &[u8; header::SAMPLE_LEN],
        first: &mut u8,
        number: &mut [u8; header::SAMPLE_OFFSET],
    ) -> Result<(), crypto::Error> {
        self.header
            .decrypt_in_place(sample, first, number)
            .map_err(crypto::Error::HeaderDecrypt)
    }
}

impl Packet<op::Open> {
    pub(in crate::security::crypto) fn open<'a>(
        &self,
        number: Number,
        header: &[u8],
        body: &'a mut [u8],
    ) -> Result<&'a [u8], rustls::Error> {
        self.packet.decrypt_in_place(number.get(), header, body)
    }
}

const _: () = {
    assert!(size_of::<Cipher<op::Seal>>() == size_of::<Cipher<op::Open>>());
};
