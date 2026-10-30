use dope_quic::conn::wire::packet::Batch;

#[derive(Default)]
pub struct Batches {
    pub initial: Batch,
    pub old_control: Batch,
    pub delayed_old_ack: Batch,
    pub release_ack: Batch,
    pub reset: Batch,
    pub reset_ack_and_probe: Batch,
    pub replacement: Replacement,
    pub drain: super::Drain,
}

#[derive(Default)]
pub struct Replacement {
    pub first: Batch,
    pub credit: Batch,
}
