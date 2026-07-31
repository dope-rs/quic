use std::num::NonZeroU16;

pub(super) trait PacketSink {
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
pub struct PacketBatch {
    pub(crate) buf: Vec<u8>,
    pub(crate) segs: Vec<u32>,
}

impl PacketBatch {
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
}

impl PacketSink for PacketBatch {
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

pub(crate) struct GsoBatch {
    pub(crate) buf: Vec<u8>,
    segment_size: Option<NonZeroU16>,
    packets: u8,
    sealed: bool,
}

impl GsoBatch {
    pub(crate) const fn new() -> Self {
        Self {
            buf: Vec::new(),
            segment_size: None,
            packets: 0,
            sealed: false,
        }
    }

    pub(crate) fn take(&mut self) -> Option<(Vec<u8>, NonZeroU16, usize)> {
        let segment_size = self.segment_size.take()?;
        let packets = usize::from(self.packets);
        self.packets = 0;
        self.sealed = false;
        Some((core::mem::take(&mut self.buf), segment_size, packets))
    }
}

impl Default for GsoBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketSink for GsoBatch {
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
        if self.sealed || usize::from(self.packets) >= dope::manifold::datagram::MAX_GSO_SEGMENTS {
            return None;
        }
        let remaining = dope::manifold::datagram::MAX_GSO_BYTES.saturating_sub(self.buf.len());
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
        let segment_size = self
            .segment_size
            .or_else(|| u16::try_from(bytes).ok().and_then(NonZeroU16::new));
        let valid = bytes != 0
            && bytes <= limit
            && self.buf.len().saturating_sub(start) == bytes
            && segment_size.is_some();
        if !valid {
            self.buf.truncate(start);
            return None;
        }
        let segment_size = segment_size.unwrap_or_else(|| unreachable!());
        self.segment_size = Some(segment_size);
        self.packets += 1;
        self.sealed = bytes < usize::from(segment_size.get());
        Some(commit)
    }

    fn is_empty(&self) -> bool {
        self.packets == 0
    }
}

impl PacketSink for Vec<Vec<u8>> {
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

pub(super) struct PacketSlot<'a> {
    pub(super) packet: &'a mut Vec<u8>,
    pub(super) emitted: bool,
}

impl PacketSink for PacketSlot<'_> {
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
