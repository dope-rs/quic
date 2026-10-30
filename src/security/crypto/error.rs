use o3::alloc;

/// Unsupported dimensions reported by native QUIC keys.
#[derive(Clone, Debug, PartialEq)]
pub struct Dimensions {
    pub sample: usize,
    pub tag: usize,
}

impl From<Dimensions> for Error {
    fn from(error: Dimensions) -> Self {
        Self::KeyDimensions {
            sample: error.sample,
            tag: error.tag,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    Limit,
    InitialSuite,
    KeyDimensions {
        sample: usize,
        tag: usize,
    },
    TagDimensions {
        actual: usize,
        required: usize,
    },
    BodyDimensions {
        actual: usize,
        available: usize,
    },
    Sample {
        actual: usize,
        required: usize,
    },
    Number {
        next: u64,
        truncated: u64,
        width: u8,
    },
    Allocation {
        error: alloc::Error,
        base: usize,
        header: usize,
        body: usize,
        tag: usize,
    },
    Encrypt(rustls::Error),
    Decrypt(rustls::Error),
    HeaderEncrypt(rustls::Error),
    HeaderDecrypt(rustls::Error),
    ReservedBits {
        actual: u8,
        mask: u8,
    },
}
