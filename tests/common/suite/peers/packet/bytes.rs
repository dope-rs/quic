use crate::common::{
    peer,
    suite::peers::{bounds, packet::Error},
};
use dope_quic::wire::{frame, packet::cid, varint::VarInt};
use o3::buffer::write::Sink;

/// RFC 9001 Appendix A vectors. RFC code components are provided under the
/// Simplified BSD License described by the RFC Trust Legal Provisions.
pub const RFC_DCID: &[u8] = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08";
pub const RFC_SCID: &[u8] = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5";
pub const RFC_HEADER: &[u8] = b"\xc1\x00\x00\x00\x01\x00\x08\xf0\x67\xa5\x50\x2a\x42\x62\xb5\x00\
    \x40\x75\x00\x01";
pub const RFC_PAYLOAD: &[u8] = b"\x02\x00\x00\x00\x00\x06\x00\x40\x5a\x02\x00\x00\x56\x03\x03\xee\
    \xfc\xe7\xf7\xb3\x7b\xa1\xd1\x63\x2e\x96\x67\x78\x25\xdd\xf7\x39\
    \x88\xcf\xc7\x98\x25\xdf\x56\x6d\xc5\x43\x0b\x9a\x04\x5a\x12\x00\
    \x13\x01\x00\x00\x2e\x00\x33\x00\x24\x00\x1d\x00\x20\x9d\x3c\x94\
    \x0d\x89\x69\x0b\x84\xd0\x8a\x60\x99\x3c\x14\x4e\xca\x68\x4d\x10\
    \x81\x28\x7c\x83\x4d\x53\x11\xbc\xf3\x2b\xb9\xda\x1a\x00\x2b\x00\
    \x02\x03\x04";
pub const RFC_WIRE: &[u8] = b"\xcf\x00\x00\x00\x01\x00\x08\xf0\x67\xa5\x50\x2a\x42\x62\xb5\x00\
    \x40\x75\xc0\xd9\x5a\x48\x2c\xd0\x99\x1c\xd2\x5b\x0a\xac\x40\x6a\
    \x58\x16\xb6\x39\x41\x00\xf3\x7a\x1c\x69\x79\x75\x54\x78\x0b\xb3\
    \x8c\xc5\xa9\x9f\x5e\xde\x4c\xf7\x3c\x3e\xc2\x49\x3a\x18\x39\xb3\
    \xdb\xcb\xa3\xf6\xea\x46\xc5\xb7\x68\x4d\xf3\x54\x8e\x7d\xde\xb9\
    \xc3\xbf\x9c\x73\xcc\x3f\x3b\xde\xd7\x4b\x56\x2b\xfb\x19\xfb\x84\
    \x02\x2f\x8e\xf4\xcd\xd9\x37\x95\xd7\x7d\x06\xed\xbb\x7a\xaf\x2f\
    \x58\x89\x18\x50\xab\xbd\xca\x3d\x20\x39\x8c\x27\x64\x56\xcb\xc4\
    \x21\x58\x40\x7d\xd0\x74\xee";

pub const WIDTH_DCID: [u8; 8] = [0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93];
pub const WIDTH_SCID: [u8; 8] = [0x23, 0x84, 0x62, 0x64, 0x33, 0x83, 0x27, 0x95];

pub fn sparse(pn: u16, offset: VarInt) -> Result<Vec<u8>, Error> {
    let frames = crypto(offset, &[0])?;
    peer::Initial::new(&bounds::INITIAL_DCID, &bounds::CLIENT_SCID, u64::from(pn))
        .seal(&frames)
        .map_err(Error::Wire)
}

pub fn notice(sequence: u8, prior: u8) -> Result<Vec<u8>, Error> {
    let id = cid::Id::try_from([0x59, sequence, 0, 0, 0, 0, 0, 0]).map_err(Error::Id)?;
    notice_with_id(sequence, prior, id.as_ref_id())
}

pub fn notice_with_id(sequence: u8, prior: u8, id: cid::Ref<'_>) -> Result<Vec<u8>, Error> {
    let mut frame = Vec::new();
    frame
        .write_slices([
            &[frame::TYPE_NEW_CONNECTION_ID],
            VarInt::from_u8(sequence).pack().as_ref(),
            VarInt::from_u8(prior).pack().as_ref(),
            &[id.length().get()],
            id.into_slice(),
            &[sequence; 16],
        ])
        .map_err(Error::Allocation)?;
    Ok(frame)
}

pub(super) fn crypto(offset: VarInt, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut frames = Vec::new();
    frame::Borrowed::crypto(offset, data)
        .map_err(|error| Error::Frame(error.into()))?
        .encode(&mut frames)
        .map_err(Error::Allocation)?;
    Ok(frames)
}

pub const DATAGRAM_PAYLOAD: &[u8] = b"d";
pub const DATAGRAM_WIDE: &[u8] = &[frame::TYPE_DATAGRAM_LEN, 0x40, 1, b'd'];

pub const RESIDENT_DATA: &[u8] = b"r";
pub const RESIDENT_CREDIT: &[u8] = &[frame::TYPE_MAX_STREAM_DATA, 0, 2];
pub const RESIDENT_STOP: &[u8] = &[frame::TYPE_STOP_SENDING, 0, 7];
pub const RESIDENT_RESET: &[u8] = &[frame::TYPE_RESET_STREAM, 2, 7, 1];
pub const HELD_FIN: &[u8] = &[
    frame::TYPE_STREAM_BASE | 3,
    0,
    5,
    b'h',
    b'e',
    b'l',
    b'd',
    b'!',
];
pub const HELD_NEXT: &[u8] = &[
    frame::TYPE_STREAM_BASE | 3,
    4,
    5,
    b'n',
    b'e',
    b'x',
    b't',
    b'!',
];
pub const HELD_BAD_RESET: &[u8] = &[frame::TYPE_RESET_STREAM, 0, 7, 4];

pub const STREAM_PROTOCOL_ERRORS: &[(&str, &[u8], u64)] = &[
    (
        "stream limit",
        &[frame::TYPE_STREAM_BASE | 2, 14, 1, b'r'],
        0x04,
    ),
    ("reset limit", &[frame::TYPE_RESET_STREAM, 14, 7, 0], 0x04),
    ("stop limit", &[frame::TYPE_STOP_SENDING, 0, 7], 0x04),
    (
        "blocked limit",
        &[frame::TYPE_STREAM_DATA_BLOCKED, 14, 0],
        0x04,
    ),
    (
        "unopened receive",
        &[frame::TYPE_STREAM_BASE | 2, 1, 1, b'r'],
        0x05,
    ),
    (
        "send-only reset",
        &[frame::TYPE_RESET_STREAM, 3, 7, 0],
        0x05,
    ),
    ("receive-only stop", &[frame::TYPE_STOP_SENDING, 2, 7], 0x05),
    (
        "receive-only credit",
        &[frame::TYPE_MAX_STREAM_DATA, 2, 1],
        0x05,
    ),
    (
        "send-only blocked",
        &[frame::TYPE_STREAM_DATA_BLOCKED, 3, 0],
        0x05,
    ),
    ("unopened stop", &[frame::TYPE_STOP_SENDING, 1, 7], 0x05),
];
pub const STREAM_AT_LIMIT: &[u8] = &[frame::TYPE_STREAM_BASE | 2, 10, 1, b'r'];

pub const ADDRESS_TOKEN: &[u8] = &[frame::TYPE_NEW_TOKEN, 1, 0x42];
