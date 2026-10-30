use std::ptr;

use aws_lc_rs::{aead, error};
use o3::{
    base::marker::ThreadBound,
    buffer::{self, write::Append, write::Sink as _},
};
use subtle::ConstantTimeEq as _;

use o3::{alloc, mem::Rejected};

use crate::wire::packet::{self, cid, decode};

pub const INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
pub const INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];
pub const INTEGRITY_TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Crypto {
    Key(error::Unspecified),
    Seal(error::Unspecified),
    Tag { actual: usize },
}

/// One worker's reusable QUIC v1 Retry integrity context.
#[derive(Debug)]
pub struct Key {
    key: aead::LessSafeKey,
    _bound: ThreadBound,
}

impl Key {
    pub fn try_new() -> Result<Self, Crypto> {
        let key =
            aead::UnboundKey::new(&aead::AES_128_GCM, &INTEGRITY_KEY_V1).map_err(Crypto::Key)?;
        Ok(Self {
            key: aead::LessSafeKey::new(key),
            _bound: ThreadBound::NEW,
        })
    }

    /// Authenticates empty plaintext with QUIC v1's fixed public key and nonce.
    pub fn tag_from_aad(&self, aad: &[u8]) -> Result<[u8; INTEGRITY_TAG_LEN], Crypto> {
        let nonce = aead::Nonce::assume_unique_for_key(INTEGRITY_NONCE_V1);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(aad), &mut [])
            .map_err(Crypto::Seal)?;
        let bytes = tag.as_ref();
        bytes.try_into().map_err(|_| Crypto::Tag {
            actual: bytes.len(),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    Allocation {
        error: alloc::Error,
        requested: usize,
    },
    Crypto(Crypto),
}

/// A structurally valid Retry borrowing its wire bytes.
#[derive(Clone, Copy)]
pub struct Ref<'wire> {
    dcid: cid::Ref<'wire>,
    scid: cid::Ref<'wire>,
    token: &'wire [u8],
    header: &'wire [u8],
    integrity_tag: &'wire [u8; INTEGRITY_TAG_LEN],
}

/// A destination-bound, integrity-verified Retry.
pub struct Verified<'wire, 'storage> {
    scid: cid::Ref<'wire>,
    token: &'storage [u8],
}

impl<'wire> Ref<'wire> {
    pub fn decode(input: &'wire [u8]) -> Result<Self, decode::Error> {
        let prefix = super::Prefix::decode(input)?.ensure(super::Type::Retry)?;
        let Some((header, token, tag)) = prefix.ids.trailer::<INTEGRITY_TAG_LEN>() else {
            return Err(decode::Error::Underflow {
                actual: input.len(),
                required: prefix.ids.end() + INTEGRITY_TAG_LEN,
            });
        };
        Ok(Self {
            dcid: prefix.ids.dcid(),
            scid: prefix.ids.scid(),
            token,
            header,
            integrity_tag: tag,
        })
    }

    pub const fn dcid(self) -> cid::Ref<'wire> {
        self.dcid
    }

    pub const fn scid(self) -> cid::Ref<'wire> {
        self.scid
    }

    pub const fn token(self) -> &'wire [u8] {
        self.token
    }

    /// Verifies Retry and promotes its token into `storage`.
    pub fn verify_into<'storage>(
        self,
        odcid: cid::Ref<'_>,
        dcid: cid::Ref<'_>,
        out: &'storage mut Vec<u8>,
    ) -> Result<Option<Verified<'wire, 'storage>>, Fault> {
        out.clear();
        if self.token.is_empty()
            || self.dcid.into_slice() != dcid.into_slice()
            || self.scid.into_slice() == odcid.into_slice()
        {
            return Ok(None);
        }
        let base = 1 + odcid.len();
        let total = base + self.header.len();
        out.write_slices([&[odcid.length().get()], odcid.into_slice(), self.header])
            .map_err(|error| Fault::Allocation {
                error,
                requested: total,
            })?;
        let want = Key::try_new()
            .and_then(|key| key.tag_from_aad(out))
            .map_err(Fault::Crypto)?;
        if !bool::from(self.integrity_tag[..].ct_eq(&want[..])) {
            out.clear();
            return Ok(None);
        }
        let size = self.token.len();
        // SAFETY: Ref retains token as a suffix of header. The successful
        // complete write admitted header.len() plus the original CID prefix
        // in this exact exclusive vector. Token therefore fits its initialized
        // prefix, and its original immutable source cannot alias that vector.
        unsafe { ptr::copy_nonoverlapping(self.token.as_ptr(), out.as_mut_ptr(), size) };
        out.truncate(size);
        Ok(Some(Verified {
            scid: self.scid,
            token: out.as_slice(),
        }))
    }
}

impl<'wire, 'storage> Verified<'wire, 'storage> {
    pub const fn scid(&self) -> cid::Ref<'wire> {
        self.scid
    }

    pub const fn token(&self) -> &'storage [u8] {
        self.token
    }
}

const _: () = assert!(usize::BITS >= 64);

/// A nonempty Retry suffix retaining its complete authenticated allocation.
#[derive(Debug)]
pub struct Suffix {
    storage: Vec<u8>,
    start: usize,
}

impl Suffix {
    pub(crate) const fn prefix_len(dcid: cid::Ref<'_>, scid: cid::Ref<'_>) -> usize {
        7 + dcid.len() + scid.len()
    }

    /// Appends an encoded Retry header and token to its retained allocation.
    pub fn encode_into(
        mut storage: Vec<u8>,
        ver: u32,
        dcid: cid::Ref<'_>,
        scid: cid::Ref<'_>,
        token: &[u8],
    ) -> Result<Suffix, Rejected<Vec<u8>, alloc::Error>> {
        let start = storage.len();
        if let Err(error) = storage.write_slices([
            &[packet::FORM_LONG | packet::FIXED_BIT | packet::LONG_RETRY],
            &ver.to_be_bytes(),
            &[dcid.length().get()],
            dcid.into_slice(),
            &[scid.length().get()],
            scid.into_slice(),
            token,
        ]) {
            return Err(Rejected::new(storage, error));
        }
        Ok(Self { storage, start })
    }
    /// Appending the first wire byte establishes the nonempty suffix.
    pub fn new(mut storage: Vec<u8>, first: u8) -> Result<Self, Rejected<Vec<u8>, alloc::Error>> {
        let start = storage.len();
        if let Err(error) = storage.write_byte(first) {
            return Err(Rejected::new(storage, error));
        }
        Ok(Self { storage, start })
    }

    pub fn append(&mut self) -> Append<'_> {
        Append::new(&mut self.storage)
    }

    pub fn storage(&self) -> &[u8] {
        &self.storage
    }

    pub fn into_storage(self) -> Vec<u8> {
        self.storage
    }
}

impl buffer::Residency for Suffix {
    fn resident(&self) -> usize {
        self.storage.capacity()
    }
}

const _: () = assert!(size_of::<Suffix>() == 4 * size_of::<usize>());

impl AsRef<[u8]> for Suffix {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: construction appends the first byte after start; exposed
        // mutations cannot shorten or replace the retained allocation.
        unsafe { self.storage.get_unchecked(self.start..) }
    }
}

impl AsMut<[u8]> for Suffix {
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: the established nonempty suffix belongs to this exclusive
        // allocation, and a slice cannot resize or replace it.
        unsafe { self.storage.get_unchecked_mut(self.start..) }
    }
}

// SAFETY: shared access preserves this exact allocation and suffix extent.
unsafe impl buffer::raw::Source for Suffix {}
