pub(super) trait PacketSink {
    fn emit<T>(
        &mut self,
        max_packet_bytes: usize,
        build: impl FnOnce(&mut Vec<u8>) -> Option<(usize, T)>,
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
    fn emit<T>(
        &mut self,
        max_packet_bytes: usize,
        build: impl FnOnce(&mut Vec<u8>) -> Option<(usize, T)>,
    ) -> Option<T> {
        let start = self.buf.len();
        match build(&mut self.buf) {
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

impl PacketSink for Vec<Vec<u8>> {
    fn emit<T>(
        &mut self,
        max_packet_bytes: usize,
        build: impl FnOnce(&mut Vec<u8>) -> Option<(usize, T)>,
    ) -> Option<T> {
        let mut pkt = Vec::new();
        if let Some((n, commit)) = build(&mut pkt) {
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
        build: impl FnOnce(&mut Vec<u8>) -> Option<(usize, T)>,
    ) -> Option<T> {
        self.packet.clear();
        let (bytes, commit) = build(self.packet)?;
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
