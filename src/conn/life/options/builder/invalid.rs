/// Exact reason connection options could not be promoted.
#[derive(Debug)]
pub enum Invalid {
    PacketJournal {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    CryptoJournal {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    ControlJournal {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    StreamJournal {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    Pmtu {
        actual: u64,
        minimum: u64,
        maximum: u64,
    },
    PendingDatagrams {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    IncomingDatagrams {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    StreamEvents {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    ReceiveSegments {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    SendBytes {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    SendResident {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    SendSegments {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    LocalBidi {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    LocalUni {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    InitialData {
        actual: u64,
        minimum: u64,
        maximum: u64,
    },
    LocalBidiData {
        actual: u64,
        minimum: u64,
        maximum: u64,
    },
    RemoteBidiData {
        actual: u64,
        minimum: u64,
        maximum: u64,
    },
    StreamUniData {
        actual: u64,
        minimum: u64,
        maximum: u64,
    },
    PeerBidi {
        actual: u64,
        minimum: u64,
        maximum: u64,
    },
    PeerUni {
        actual: u64,
        minimum: u64,
        maximum: u64,
    },
    ConnectionIds {
        actual: u64,
        minimum: u64,
        maximum: u64,
    },
    Reconnect,
}
