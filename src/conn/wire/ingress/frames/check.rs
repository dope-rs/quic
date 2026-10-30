use crate::{conn, stream, wire::frame};
use conn::stream::{Access, state::receive};
use conn::wire::ingress::frames;
use frames::record;
use o3::buffer;

pub(super) fn validate<B: stream::Recv, D: buffer::raw::Segment>(
    state: &receive::Update<'_, B, D>,
    records: &[record::FrameRecord<'_>],
    next: u64,
    cid: Option<&frames::PacketCid<'_>>,
) -> Result<(), conn::Error> {
    for record in records {
        match record.view() {
            frame::View::Ack { largest: last, .. } if last.get() >= next => {
                return Err(conn::Error::ProtocolViolation);
            }
            frame::View::RetireConnectionId { .. } if cid.is_none() => {
                return Err(conn::Error::ProtocolViolation);
            }
            frame::View::StreamDataBlocked { stream_id: id, .. } => {
                state.try_peer(id, Access::Receive)?;
            }
            _ => {}
        }
    }
    Ok(())
}
