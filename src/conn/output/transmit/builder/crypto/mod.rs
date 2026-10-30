use crate::conn;
use crate::conn::output::transmit;
use crate::conn::wire::crypto::tx;
use crate::wire::{frame, varint};

use frame::decode::error;
use o3::{alloc, buffer::write::Sink};

mod room;
pub(in crate::conn) use room::Room;

pub(in crate::conn::output::transmit::builder) fn append<const PROBE: bool>(
    crypto: &tx::Tx,
    commit: &mut Option<tx::Commit>,
    epoch: conn::Epoch,
    room: usize,
    out: &mut impl Sink<Error = alloc::Error>,
) -> Result<(), transmit::Admission> {
    let selected = if PROBE {
        crypto.select_probe(epoch, |record| Room::new(room).limit(record.offset()))
    } else {
        crypto.select(epoch, |record| Room::new(room).limit(record.offset()))
    };
    let Some(selected) = selected else {
        return Ok(());
    };
    let record = selected.commit.record();
    let offset = varint::VarInt::new(record.offset()).ok_or(transmit::Admission::Encoding {
        epoch,
        error: error::Fault::InvalidLength {
            offset: record.offset(),
            length: selected.data.len() as u64,
        },
    })?;
    let frame = frame::Borrowed::crypto(offset, selected.data)
        .map_err(|error| transmit::Admission::Encoding { epoch, error })?;
    let needed = 1
        + usize::from(offset.encoded_len())
        + varint::VarInt::width(selected.data.len())
        + selected.data.len();
    frame
        .encode(out)
        .map_err(|error| transmit::Admission::Payload {
            error,
            requested: needed,
        })?;
    *commit = Some(selected.commit);
    Ok(())
}
