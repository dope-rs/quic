use o3::{alloc, buffer::write::consume};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cid {
    Destination,
    Source,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Length {
    Token,
    Tagged,
    Packet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Cid {
        field: Cid,
        cause: consume::Error,
    },
    Number {
        actual: u64,
        maximum: u64,
    },
    Width {
        actual: u8,
        minimum: u8,
        maximum: u8,
    },
    Length {
        field: Length,
        actual: usize,
        maximum: u64,
    },
    Overflow {
        field: Length,
        base: usize,
        added: usize,
    },
    Allocation {
        error: alloc::Error,
        requested: usize,
    },
}

const _: () = assert!(!std::mem::needs_drop::<Error>());
