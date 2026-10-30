/// Why QUIC retired a send-queue owner.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    Acked,
    Stopped,
    Reset,
    Closed,
    PeerRetired,
}
