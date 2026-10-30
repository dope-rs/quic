use crate::{errors, wire::varint};

/// Wire-distinct proto and app `CONNECTION_CLOSE` payloads.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Transport {
        error_code: varint::VarInt,
        frame_type: varint::VarInt,
    },
    Application(errors::Code),
}

const _: () = assert!(
    std::mem::size_of::<Code>() <= std::mem::size_of::<(bool, varint::VarInt, varint::VarInt)>()
);
