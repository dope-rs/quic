use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct RecvStream {
    assembled: Vec<u8>,
    delivered_to: u64,
    received_to: u64,
    highest_offset: u64,
    gaps: BTreeMap<u64, Vec<u8>>,
    final_size: Option<u64>,
    reset_error: Option<u64>,
}

impl RecvStream {
    pub fn highest_offset(&self) -> u64 {
        self.highest_offset
    }

    pub fn on_chunk(&mut self, offset: u64, data: &[u8], fin: bool) {
        let end = offset + data.len() as u64;
        if end > self.highest_offset {
            self.highest_offset = end;
        }
        if fin {
            self.final_size = Some(offset + data.len() as u64);
        }
        if end <= self.received_to {
            return;
        }
        let (off, bytes): (u64, &[u8]) = if offset < self.received_to {
            let skip = (self.received_to - offset) as usize;
            (self.received_to, &data[skip..])
        } else {
            (offset, data)
        };
        if off == self.received_to {
            self.assembled.extend_from_slice(bytes);
            self.received_to += bytes.len() as u64;
            self.drain_gaps();
        } else {
            self.gaps.insert(off, bytes.to_vec());
        }
    }

    fn drain_gaps(&mut self) {
        while let Some((&g_off, _)) = self.gaps.range(..=self.received_to).next_back() {
            let g = self.gaps.remove(&g_off).expect("just located");
            let g_end = g_off + g.len() as u64;
            if g_end <= self.received_to {
                continue;
            }
            let skip = (self.received_to - g_off) as usize;
            self.assembled.extend_from_slice(&g[skip..]);
            self.received_to = g_end;
        }
    }

    pub fn read(&mut self, dst: &mut Vec<u8>) -> usize {
        let n = self.assembled.len();
        dst.extend_from_slice(&self.assembled);
        self.assembled.clear();
        self.delivered_to += n as u64;
        n
    }

    pub fn is_eof(&self) -> bool {
        matches!(self.final_size, Some(size) if size == self.delivered_to)
    }

    pub fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    pub fn on_reset(&mut self, error_code: u64, final_size: u64) {
        self.reset_error = Some(error_code);
        self.final_size = Some(final_size);
        if final_size > self.highest_offset {
            self.highest_offset = final_size;
        }
    }

    pub fn reset_error(&self) -> Option<u64> {
        self.reset_error
    }
}

#[derive(Debug, Default)]
pub struct SendStream {
    buf: Vec<u8>,
    base_offset: u64,
    sent_rel: usize,
    acked: BTreeMap<u64, u64>,
    fin_marked: bool,
    fin_sent: bool,
    fin_acked: bool,
    stop_sending_error: Option<u64>,
    reset_sent: bool,
}

impl SendStream {
    pub fn write(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn mark_fin(&mut self) {
        self.fin_marked = true;
    }

    pub fn has_pending(&self) -> bool {
        self.sent_rel < self.buf.len() || (self.fin_marked && !self.fin_sent)
    }

    pub fn next_offset(&self) -> u64 {
        self.base_offset + self.sent_rel as u64
    }

    pub fn unsent(&self) -> (u64, &[u8]) {
        (
            self.base_offset + self.sent_rel as u64,
            &self.buf[self.sent_rel..],
        )
    }

    pub fn would_fin(&self, take: usize) -> bool {
        self.fin_marked && self.sent_rel + take >= self.buf.len()
    }

    pub fn blocked(&self) -> bool {
        self.fin_sent || self.reset_sent
    }

    pub fn chunk_at(&self, offset: u64, len: u64) -> Option<&[u8]> {
        if offset < self.base_offset {
            return None;
        }
        let start = (offset - self.base_offset) as usize;
        let end = start + len as usize;
        if end > self.buf.len() {
            return None;
        }
        Some(&self.buf[start..end])
    }

    pub fn advance_sent(&mut self, n: usize, fin_now: bool) {
        self.sent_rel += n;
        if fin_now {
            self.fin_sent = true;
        }
    }

    pub fn fin_sent(&self) -> bool {
        self.fin_sent
    }

    pub fn mark_fin_acked(&mut self) {
        self.fin_acked = true;
    }

    pub fn ack(&mut self, offset: u64, len: u64) {
        if len == 0 {
            return;
        }
        let mut start = offset;
        let mut end = offset + len;
        let mut overlapping: Vec<u64> = Vec::new();
        for (&s, &e) in self.acked.range(..=end) {
            if e >= start {
                start = start.min(s);
                end = end.max(e);
                overlapping.push(s);
            }
        }
        for s in overlapping {
            self.acked.remove(&s);
        }
        self.acked.insert(start, end);

        if let Some((&s0, &e0)) = self.acked.iter().next()
            && s0 <= self.base_offset
            && e0 > self.base_offset
        {
            let drain_n = ((e0 - self.base_offset) as usize).min(self.buf.len());
            self.buf.drain(..drain_n);
            self.base_offset += drain_n as u64;
            self.sent_rel = self.sent_rel.saturating_sub(drain_n);
            self.acked.remove(&s0);
        }
    }

    pub fn is_fully_acked(&self) -> bool {
        self.fin_acked && self.buf.is_empty()
    }

    pub fn on_stop_sending(&mut self, error_code: u64) {
        self.stop_sending_error = Some(error_code);
        self.buf.clear();
        self.sent_rel = 0;
    }

    pub fn stop_sending_error(&self) -> Option<u64> {
        self.stop_sending_error
    }

    pub fn mark_reset_sent(&mut self) {
        self.reset_sent = true;
        self.buf.clear();
        self.sent_rel = 0;
    }

    pub fn reset_sent(&self) -> bool {
        self.reset_sent
    }
}
