use o3::alloc::{self, VecExt};
use o3::base::marker::ThreadBound;
use rustls::crypto::cipher::{AeadKey, Iv};
use rustls::version::TLS13;
use rustls::{ServerConfig, Side, SupportedCipherSuite, crypto::aws_lc_rs::cipher_suite, quic};
use std::sync::Arc;

/// Selects one suite while retaining the fixture's native signing identity.
pub fn suite(config: &mut ServerConfig, suite: SupportedCipherSuite) -> Result<(), rustls::Error> {
    let mut provider = config.crypto_provider().as_ref().clone();
    provider.cipher_suites = vec![suite];
    let mut next = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::clone(&config.cert_resolver));
    next.send_tls13_tickets = 0;
    *config = next;
    Ok(())
}

const MAX_NUMBER: u64 = (1 << 62) - 1;
const MAX_WIDTH: usize = 4;
const SAMPLE_OFFSET: usize = 4;
const SAMPLE_LEN: usize = 16;
const SAMPLE_END: usize = SAMPLE_OFFSET + SAMPLE_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewError {
    Number { actual: u64, maximum: u64 },
}

#[derive(Clone, Debug, PartialEq)]
pub enum SealError {
    Number {
        actual: u64,
        maximum: u64,
    },
    Sequence {
        expected: u64,
        actual: u64,
    },
    Limit {
        actual: u64,
        maximum: u64,
    },
    Width {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    Header {
        offset: usize,
        width: usize,
        len: usize,
    },
    Overflow {
        base: usize,
        added: usize,
    },
    Sample {
        start: usize,
        end: usize,
        len: usize,
    },
    Aead(rustls::Error),
    Allocation(alloc::Error),
    Protection(rustls::Error),
}

/// Wire-fixture authority for RFC vectors and adversarial ingress.
pub struct Raw {
    keys: quic::DirectionalKeys,
    next_packet_number: u64,
    encrypted: u64,
    _bound: ThreadBound,
}

impl Raw {
    pub fn initial(dcid: &[u8], side: Side, next: u64) -> Result<Self, NewError> {
        let suite = match cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .and_then(|suite| suite.quic_suite())
        {
            Some(suite) => suite,
            None => unreachable!("provider"),
        };
        Self::from_keys(suite.keys(dcid, side, quic::Version::V1).local, next)
    }

    pub fn from_keys(keys: quic::DirectionalKeys, next: u64) -> Result<Self, NewError> {
        if next > MAX_NUMBER {
            return Err(NewError::Number {
                actual: next,
                maximum: MAX_NUMBER,
            });
        }
        Ok(Self {
            keys,
            next_packet_number: next,
            encrypted: 0,
            _bound: ThreadBound::NEW,
        })
    }

    pub fn open(&mut self, wire: &mut [u8], offset: usize) -> Result<(u64, Vec<u8>), SealError> {
        let end = offset.checked_add(SAMPLE_END).ok_or(SealError::Overflow {
            base: offset,
            added: SAMPLE_END,
        })?;
        let start = offset + SAMPLE_OFFSET;
        let sample = wire.get(start..end).ok_or(SealError::Sample {
            start,
            end,
            len: wire.len(),
        })?;
        let sample: [u8; SAMPLE_LEN] = match sample.try_into() {
            Ok(sample) => sample,
            Err(_) => unreachable!("sample"),
        };
        let mut data = Vec::try_new(wire.len()).map_err(SealError::Allocation)?;
        let mut first = wire[0];
        self.keys
            .header
            .decrypt_in_place(&sample, &mut first, &mut wire[offset..start])
            .map_err(SealError::Protection)?;
        wire[0] = first;
        let width = usize::from(wire[0] & 3) + 1;
        let mut number = 0;
        for byte in &wire[offset..offset + width] {
            number = (number << 8) | u64::from(*byte);
        }
        if number != self.next_packet_number {
            return Err(SealError::Sequence {
                expected: self.next_packet_number,
                actual: number,
            });
        }
        let (head, body) = wire.split_at_mut(offset + width);
        let bytes = self
            .keys
            .packet
            .decrypt_in_place(number, head, body)
            .map_err(SealError::Aead)?;
        data.extend_from_slice(bytes);
        self.next_packet_number += 1;
        Ok((number, data))
    }

    pub fn seal(
        &mut self,
        header: &[u8],
        data: &[u8],
        pn: u64,
        off: usize,
        width: usize,
    ) -> Result<Vec<u8>, SealError> {
        if pn > MAX_NUMBER {
            return Err(SealError::Number {
                actual: pn,
                maximum: MAX_NUMBER,
            });
        }
        if pn != self.next_packet_number {
            return Err(SealError::Sequence {
                expected: self.next_packet_number,
                actual: pn,
            });
        }
        let limit = self.keys.packet.confidentiality_limit();
        if self.encrypted >= limit {
            return Err(SealError::Limit {
                actual: self.encrypted,
                maximum: limit,
            });
        }
        if width == 0 || width > MAX_WIDTH {
            return Err(SealError::Width {
                actual: width,
                minimum: 1,
                maximum: MAX_WIDTH,
            });
        }
        let end = add(off, width)?;
        if end != header.len() {
            return Err(SealError::Header {
                offset: off,
                width,
                len: header.len(),
            });
        }

        let tag_len = self.keys.packet.tag_len();
        let min = SAMPLE_END.saturating_sub(width.saturating_add(tag_len));
        let need = data.len().max(min);
        let body = add(header.len(), need)?;
        let total = add(body, tag_len)?;
        let begin = add(off, SAMPLE_OFFSET)?;
        let tail = add(begin, SAMPLE_LEN)?;
        if tail > total {
            return Err(SealError::Sample {
                start: begin,
                end: tail,
                len: total,
            });
        }

        let mut out = Vec::try_new(total).map_err(SealError::Allocation)?;
        out.extend_from_slice(header);
        out.extend_from_slice(data);
        out.resize(body, 0);
        let tag = self
            .keys
            .packet
            .encrypt_in_place(pn, header, &mut out[header.len()..body])
            .map_err(SealError::Aead)?;
        out.extend_from_slice(tag.as_ref());
        let Some(bytes) = out.get(begin..tail) else {
            return Err(SealError::Sample {
                start: begin,
                end: tail,
                len: out.len(),
            });
        };
        let mut sample = [0; SAMPLE_LEN];
        sample.copy_from_slice(bytes);
        let mut first = out[0];
        self.keys
            .header
            .encrypt_in_place(&sample, &mut first, &mut out[off..end])
            .map_err(SealError::Protection)?;
        out[0] = first;
        self.next_packet_number = pn + 1;
        self.encrypted += 1;
        Ok(out)
    }
}

fn add(base: usize, added: usize) -> Result<usize, SealError> {
    base.checked_add(added)
        .ok_or(SealError::Overflow { base, added })
}

/// A native AWS-LC suite with selected metadata and header-operation failures.
pub struct Dimensions<
    'key,
    const SAMPLE: usize,
    const TAG: usize,
    const ENCRYPT: bool = false,
    const DECRYPT: bool = false,
    const BODY: bool = false,
> {
    alg: &'key dyn quic::Algorithm,
}

impl<
    const SAMPLE: usize,
    const TAG: usize,
    const ENCRYPT: bool,
    const DECRYPT: bool,
    const BODY: bool,
> Dimensions<'_, SAMPLE, TAG, ENCRYPT, DECRYPT, BODY>
{
    pub const SUITE: Option<rustls::SupportedCipherSuite> =
        match cipher_suite::TLS13_AES_128_GCM_SHA256.tls13() {
            Some(suite) => match suite.quic {
                Some(alg) => Some(rustls::SupportedCipherSuite::Tls13(
                    &rustls::Tls13CipherSuite {
                        common: rustls::CipherSuiteCommon {
                            suite: suite.common.suite,
                            hash_provider: suite.common.hash_provider,
                            confidentiality_limit: suite.common.confidentiality_limit,
                        },
                        hkdf_provider: suite.hkdf_provider,
                        aead_alg: suite.aead_alg,
                        quic: Some(&Dimensions::<SAMPLE, TAG, ENCRYPT, DECRYPT, BODY> { alg }),
                    },
                )),
                None => None,
            },
            None => None,
        };
}

impl<
    const SAMPLE: usize,
    const TAG: usize,
    const ENCRYPT: bool,
    const DECRYPT: bool,
    const BODY: bool,
> quic::Algorithm for Dimensions<'_, SAMPLE, TAG, ENCRYPT, DECRYPT, BODY>
{
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(Dimension::<_, TAG, false, false, BODY>(
            self.alg.packet_key(key, iv),
        ))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(Dimension::<_, SAMPLE, ENCRYPT, DECRYPT>(
            self.alg.header_protection_key(key),
        ))
    }

    fn aead_key_len(&self) -> usize {
        self.alg.aead_key_len()
    }
}

struct Dimension<
    K,
    const N: usize,
    const ENCRYPT: bool = false,
    const DECRYPT: bool = false,
    const BODY: bool = false,
>(K);

impl<const N: usize, const BODY: bool> quic::PacketKey
    for Dimension<Box<dyn quic::PacketKey>, N, false, false, BODY>
{
    fn encrypt_in_place(
        &self,
        number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, rustls::Error> {
        self.0.encrypt_in_place(number, header, payload)
    }

    fn decrypt_in_place<'a>(
        &self,
        number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], rustls::Error> {
        let plain = self.0.decrypt_in_place(number, header, payload)?;
        if BODY { Ok(&[0; 65_536]) } else { Ok(plain) }
    }

    fn tag_len(&self) -> usize {
        N
    }

    fn confidentiality_limit(&self) -> u64 {
        self.0.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }
}

impl<const N: usize, const ENCRYPT: bool, const DECRYPT: bool> quic::HeaderProtectionKey
    for Dimension<Box<dyn quic::HeaderProtectionKey>, N, ENCRYPT, DECRYPT>
{
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        if ENCRYPT {
            return Err(rustls::Error::EncryptError);
        }
        self.0.encrypt_in_place(sample, first, number)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        if DECRYPT {
            return Err(rustls::Error::DecryptError);
        }
        self.0.decrypt_in_place(sample, first, number)
    }

    fn sample_len(&self) -> usize {
        N
    }
}
