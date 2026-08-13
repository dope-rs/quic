use crate::conn::retired::remove::Remove as _;

use crate::conn::retired;

struct Retire<'a, Tag> {
    sequence: &'a mut Sequence<Tag>,
    index: u64,
}

impl<Tag> Retire<'_, Tag> {
    fn commit(self) -> Result<bool, retired::Full> {
        let sequence = self.sequence;
        let index = self.index;
        if index < sequence.contiguous {
            return Ok(false);
        }
        if index == sequence.contiguous {
            sequence.contiguous += 1;
            if let Some(first) = sequence.ranges.first()
                && first.start == sequence.contiguous
            {
                assert!(sequence.ranges.remove(first.start));
                sequence.contiguous = first.end;
            }
            return Ok(true);
        }

        let mut neighbors = sequence.ranges.neighbors(index);
        let left = neighbors.left();
        if left.is_some_and(|range| index < range.end) {
            return Ok(false);
        }
        let right = neighbors.right();
        let joins_left = left.is_some_and(|range| range.end == index);
        let joins_right = right.is_some_and(|range| range.start == index + 1);
        match (left, right, joins_left, joins_right) {
            (Some(_), Some(right), true, true) => {
                neighbors.extend_left(right.end);
                neighbors.remove_right();
            }
            (Some(_), _, true, false) => neighbors.extend_left(index + 1),
            (_, Some(_), false, true) => neighbors.extend_right(index),
            _ => neighbors.insert(crate::conn::retired::storage::Interval {
                start: index,
                end: index + 1,
            })?,
        }
        Ok(true)
    }
}

/// One monotonically opened stream-number sequence. The cursor lifetime keeps
/// every structural index inside the exclusive mutation that produced it.
pub(super) struct Sequence<Tag> {
    pub(super) contiguous: u64,
    /// Each retained interval requires a distinct live hole before it.
    pub(super) ranges: retired::Tree<Tag>,
}

impl<Tag> Sequence<Tag> {
    pub(super) fn new(live_capacity: usize) -> Self {
        Self {
            contiguous: 0,
            ranges: retired::Tree::new(live_capacity),
        }
    }

    pub(super) fn retire(&mut self, index: u64) -> Result<bool, retired::Full> {
        Retire {
            sequence: self,
            index,
        }
        .commit()
    }

    pub(super) fn contains(&self, index: u64) -> bool {
        index < self.contiguous || self.ranges.contains(index)
    }
}

enum LocalBidiRecv {}
enum PeerBidiRecv {}
enum PeerUniRecv {}
enum PeerBidiSend {}

/// Fully-retired stream halves. Impossible local-unidirectional receive state
/// has no lane, and every real lane owns a separately branded fixed tree.
pub(in crate::conn) struct Streams {
    local_bidi_recv: Sequence<LocalBidiRecv>,
    peer_bidi_recv: Sequence<PeerBidiRecv>,
    peer_uni_recv: Sequence<PeerUniRecv>,
    peer_bidi_send: Sequence<PeerBidiSend>,
}

impl Streams {
    pub(in crate::conn) fn new(
        local_bidi_capacity: usize,
        peer_bidi_capacity: usize,
        peer_uni_capacity: usize,
    ) -> Self {
        Self {
            local_bidi_recv: Sequence::new(local_bidi_capacity),
            peer_bidi_recv: Sequence::new(peer_bidi_capacity),
            peer_uni_recv: Sequence::new(peer_uni_capacity),
            peer_bidi_send: Sequence::new(peer_bidi_capacity),
        }
    }

    pub(in crate::conn) fn retire_recv(
        &mut self,
        id: u64,
        is_client: bool,
    ) -> Result<bool, retired::Full> {
        let uni = id & 0x2 != 0;
        let local = (id & 0x1 == 0) == is_client;
        match (local, uni) {
            (true, false) => self.local_bidi_recv.retire(id >> 2),
            (false, false) => self.peer_bidi_recv.retire(id >> 2),
            (false, true) => self.peer_uni_recv.retire(id >> 2),
            (true, true) => Ok(false),
        }
    }

    pub(in crate::conn) fn recv_contains(&self, id: u64, is_client: bool) -> bool {
        let uni = id & 0x2 != 0;
        let local = (id & 0x1 == 0) == is_client;
        match (local, uni) {
            (true, false) => self.local_bidi_recv.contains(id >> 2),
            (false, false) => self.peer_bidi_recv.contains(id >> 2),
            (false, true) => self.peer_uni_recv.contains(id >> 2),
            (true, true) => false,
        }
    }

    pub(in crate::conn) fn retire_peer_bidi_send(
        &mut self,
        id: u64,
    ) -> Result<bool, retired::Full> {
        self.peer_bidi_send.retire(id >> 2)
    }

    pub(in crate::conn) fn peer_bidi_send_contains(&self, id: u64) -> bool {
        self.peer_bidi_send.contains(id >> 2)
    }
}
