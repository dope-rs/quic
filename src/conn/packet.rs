use std::{num, ops};

pub(super) struct Payload<'a> {
    out: &'a mut Vec<u8>,
    start: usize,
}

impl<'a> Payload<'a> {
    pub(super) fn new(out: &'a mut Vec<u8>, start: usize) -> Self {
        Self { out, start }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.out.len() == self.start
    }

    pub(super) fn out_mut(&mut self) -> &mut Vec<u8> {
        self.out
    }
}

impl ops::Deref for Payload<'_> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        self.out
    }
}

impl ops::DerefMut for Payload<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.out
    }
}

impl Extend<u8> for Payload<'_> {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.out.extend(iter);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cargo {
    CryptoOrAck,
    DatagramOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CryptoMode {
    Regular,
    PtoProbe,
}

pub(super) trait Sink {
    const FRESH_PACKETS: bool = false;

    fn reset(&mut self, max_packets: usize, max_packet_bytes: usize) {
        let _ = (max_packets, max_packet_bytes);
    }

    fn emit<T>(
        &mut self,
        max_packet_bytes: usize,
        build: impl FnOnce(&mut Vec<u8>, usize) -> Option<(usize, T)>,
    ) -> Option<T>;
    fn is_empty(&self) -> bool;
}

#[derive(Default)]
pub struct Batch {
    pub(crate) buf: Vec<u8>,
    pub(crate) segs: Vec<u32>,
}

impl Batch {
    pub(crate) fn clear(&mut self) {
        self.buf.clear();
        self.segs.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.segs.is_empty()
    }

    pub fn byte_len(&self) -> usize {
        self.buf.len()
    }

    pub fn packets(&self) -> usize {
        self.segs.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.segs.iter().scan(0usize, |offset, &length| {
            let start = *offset;
            *offset += length as usize;
            Some(&self.buf[start..*offset])
        })
    }

    /// Iterates over packet storage for in-place delivery to a receiver.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut [u8]> {
        let mut rest = self.buf.as_mut_slice();
        self.segs.iter().map(move |&length| {
            let (packet, tail) = core::mem::take(&mut rest).split_at_mut(length as usize);
            rest = tail;
            packet
        })
    }
}

impl Sink for Batch {
    fn reset(&mut self, max_packets: usize, max_packet_bytes: usize) {
        self.clear();
        self.buf
            .reserve(max_packets.saturating_mul(max_packet_bytes));
        self.segs.reserve(max_packets);
    }

    fn emit<T>(
        &mut self,
        max_packet_bytes: usize,
        build: impl FnOnce(&mut Vec<u8>, usize) -> Option<(usize, T)>,
    ) -> Option<T> {
        let start = self.buf.len();
        match build(&mut self.buf, max_packet_bytes) {
            Some((n, commit))
                if n <= max_packet_bytes
                    && self.buf.len().saturating_sub(start) == n
                    && u32::try_from(n).is_ok() =>
            {
                self.segs.push(n as u32);
                Some(commit)
            }
            Some(_) | None => {
                self.buf.truncate(start);
                None
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.segs.is_empty()
    }
}

pub(crate) struct Gso {
    pub(crate) buf: Vec<u8>,
    limits: dope::core::io::datagram::GsoLimits,
    segment_size: Option<num::NonZeroU16>,
    packets: u8,
    sealed: bool,
}

impl Gso {
    pub(crate) const fn new(limits: dope::core::io::datagram::GsoLimits) -> Self {
        Self {
            buf: Vec::new(),
            limits,
            segment_size: None,
            packets: 0,
            sealed: false,
        }
    }

    pub(crate) const fn limits(&self) -> dope::core::io::datagram::GsoLimits {
        self.limits
    }

    pub(crate) fn take(&mut self) -> Option<(Vec<u8>, num::NonZeroU16, usize)> {
        let segment_size = self.segment_size.take()?;
        let packets = usize::from(self.packets);
        self.packets = 0;
        self.sealed = false;
        Some((core::mem::take(&mut self.buf), segment_size, packets))
    }
}

impl Sink for Gso {
    fn reset(&mut self, max_packets: usize, max_packet_bytes: usize) {
        self.buf.clear();
        self.segment_size = None;
        self.packets = 0;
        self.sealed = false;
        self.buf
            .reserve(max_packets.saturating_mul(max_packet_bytes));
    }

    fn emit<T>(
        &mut self,
        max_packet_bytes: usize,
        build: impl FnOnce(&mut Vec<u8>, usize) -> Option<(usize, T)>,
    ) -> Option<T> {
        if self.sealed || usize::from(self.packets) >= self.limits.max_segments {
            return None;
        }
        let remaining = self.limits.max_bytes.saturating_sub(self.buf.len());
        let limit = self
            .segment_size
            .map_or(max_packet_bytes, |size| {
                max_packet_bytes.min(usize::from(size.get()))
            })
            .min(remaining);
        if limit == 0 {
            return None;
        }
        let start = self.buf.len();
        let Some((bytes, commit)) = build(&mut self.buf, limit) else {
            self.buf.truncate(start);
            return None;
        };
        let Some(segment_size) = self
            .segment_size
            .or_else(|| u16::try_from(bytes).ok().and_then(num::NonZeroU16::new))
        else {
            self.buf.truncate(start);
            return None;
        };
        let valid = bytes != 0 && bytes <= limit && self.buf.len().saturating_sub(start) == bytes;
        if !valid {
            self.buf.truncate(start);
            return None;
        }
        self.segment_size = Some(segment_size);
        self.packets += 1;
        self.sealed = bytes < usize::from(segment_size.get());
        Some(commit)
    }

    fn is_empty(&self) -> bool {
        self.packets == 0
    }
}

impl Sink for Vec<Vec<u8>> {
    const FRESH_PACKETS: bool = true;

    fn emit<T>(
        &mut self,
        max_packet_bytes: usize,
        build: impl FnOnce(&mut Vec<u8>, usize) -> Option<(usize, T)>,
    ) -> Option<T> {
        let mut pkt = Vec::new();
        if let Some((n, commit)) = build(&mut pkt, max_packet_bytes) {
            if n <= max_packet_bytes && pkt.len() == n {
                self.push(pkt);
                Some(commit)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

pub(super) struct Slot<'a> {
    pub(super) packet: &'a mut Vec<u8>,
    pub(super) emitted: bool,
}

impl Sink for Slot<'_> {
    fn emit<T>(
        &mut self,
        max_packet_bytes: usize,
        build: impl FnOnce(&mut Vec<u8>, usize) -> Option<(usize, T)>,
    ) -> Option<T> {
        self.packet.clear();
        let Some((bytes, commit)) = build(self.packet, max_packet_bytes) else {
            self.packet.clear();
            return None;
        };
        if bytes > max_packet_bytes || self.packet.len() != bytes {
            self.packet.clear();
            return None;
        }
        self.emitted = true;
        Some(commit)
    }

    fn is_empty(&self) -> bool {
        !self.emitted
    }
}
