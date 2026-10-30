pub(super) const EVENT: u32 = 1 << 31;
pub(super) const SLOT_MASK: u32 = !EVENT;
pub(super) const SLOT_NONE: u32 = SLOT_MASK;
pub(super) const SLOT_CLAIMED: u32 = SLOT_NONE - 1;
pub(super) const BINDING_NONE: u32 = u32::MAX;
pub(super) const BINDING_UNBOUND: u32 = BINDING_NONE - 1;

pub(super) struct Node {
    pub(super) send: u32,
    pub(super) receive: u32,
    pub(super) binding: u32,
}

impl Node {
    pub(super) const fn new() -> Self {
        Self {
            send: SLOT_NONE,
            receive: SLOT_NONE,
            binding: BINDING_NONE,
        }
    }

    pub(super) const fn word<const SEND: bool>(&self) -> u32 {
        if SEND { self.send } else { self.receive }
    }

    pub(super) fn word_mut<const SEND: bool>(&mut self) -> &mut u32 {
        if SEND {
            &mut self.send
        } else {
            &mut self.receive
        }
    }

    pub(super) const fn is_live(&self) -> bool {
        self.send != SLOT_NONE || self.receive != SLOT_NONE || self.binding != BINDING_NONE
    }
}

const _: () = assert!(std::mem::size_of::<Node>() == 3 * std::mem::size_of::<u32>());
