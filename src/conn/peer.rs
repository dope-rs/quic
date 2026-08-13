/// Number of peer-initiated streams opened in each direction. QUIC opens all
/// lower-numbered streams of the same type implicitly, so a frontier is the
/// complete proof and no per-stream set is needed.
#[derive(Default)]
pub(super) struct Streams {
    bidi: u64,
    uni: u64,
}

impl Streams {
    pub(super) fn contains(&self, id: u64) -> bool {
        id >> 2 < self.count(id & 0x2 != 0)
    }

    pub(super) fn open(&mut self, id: u64) {
        let count = (id >> 2).saturating_add(1);
        let frontier = if id & 0x2 != 0 {
            &mut self.uni
        } else {
            &mut self.bidi
        };
        *frontier = (*frontier).max(count);
    }

    fn count(&self, uni: bool) -> u64 {
        if uni { self.uni } else { self.bidi }
    }
}
