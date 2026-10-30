use dope_quic::conn::wire::packet::Batch;

#[derive(Default)]
pub struct Batches {
    pub original: Batch,
    pub first_ack: Batch,
    pub probe: Batch,
    pub late_ack: Batch,
    pub drain: super::Drain,
}
