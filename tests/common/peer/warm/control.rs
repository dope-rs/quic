use dope_quic::conn::wire::packet::Batch;

#[derive(Default)]
pub struct Batches {
    pub original: Batch,
    pub first_ack: Batch,
    pub probe: Batch,
    pub late_probe_ack: Batch,
    pub replacement: Batch,
    pub replacement_response: Batch,
    pub final_ack: Batch,
}
