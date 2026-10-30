use crate::conn::wire::storage;
use o3::depot::capacity;
use std::num::NonZero;

mod queue;
pub(in crate::conn) mod raw;
mod replies;
mod view;

pub(in crate::conn) use queue::{Challenges, Queue};
pub(in crate::conn) use replies::Replies;
pub(in crate::conn) use view::View;

use crate::conn;
use crate::conn::output::control;
use crate::conn::wire::path;
use crate::wire::varint;
use control::journal::storage::Set;

use control::kind;
use control::owner;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    State {
        state: conn::State,
        data: [u8; 8],
    },
    Duplicate {
        data: [u8; 8],
    },
    Capacity {
        data: [u8; 8],
        reason: capacity::Reason,
    },
    Keys {
        data: [u8; 8],
        next: NonZero<u64>,
    },
}

pub(in crate::conn) enum Completion {
    Unmatched,
    Accepted(Option<path::Key>),
}

/// A position selected in an original ready prefix; publication retains its owner.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::conn) struct Position(u8);

pub(in crate::conn) struct Encoded {
    pub(in crate::conn) data: [u8; 8],
    pub(in crate::conn) position: Position,
}

pub(in crate::conn) struct Relocated {
    from: Position,
    to: Position,
}

impl Relocated {
    pub(in crate::conn) fn apply(&self, position: &mut Position) {
        if *position == self.from {
            *position = self.to;
        }
    }
}

struct Challenge {
    key: path::ControlKey,
    data: [u8; 8],
    control: Option<owner::Key<kind::Challenge>>,
    outstanding: bool,
    path: Option<path::Key>,
}

struct Reply {
    key: path::ControlKey,
    data: [u8; 8],
    control: Option<owner::Key<kind::PathResponse>>,
    path: Option<path::Key>,
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct Flags(u8);

impl Flags {
    const STATELESS_RESET_RECEIVED: u8 = 1 << 0;
    const RETRY_PROCESSED: u8 = 1 << 1;

    const fn new() -> Self {
        Self(0)
    }

    fn reset(&mut self) {
        self.0 |= Self::STATELESS_RESET_RECEIVED;
    }

    const fn is_reset(self) -> bool {
        self.0 & Self::STATELESS_RESET_RECEIVED != 0
    }

    fn retry(&mut self) {
        self.0 |= Self::RETRY_PROCESSED;
    }

    const fn is_retry(self) -> bool {
        self.0 & Self::RETRY_PROCESSED != 0
    }
}

pub(in crate::conn) struct State {
    challenges: storage::Split<Challenge, { conn::MAX_PATH_TOKENS }>,
    validated_tokens: storage::Vec<[u8; 8], { conn::MAX_PATH_TOKENS }>,
    response_controls: storage::Split<Reply, { conn::MAX_PATH_TOKENS }>,
    retirements: storage::Split<
        (varint::VarInt, Option<owner::Key<kind::RetireCid>>),
        { conn::MAX_PENDING_RETIRE_CONNECTION_IDS },
    >,
    retired: u64,
    flags: Flags,
    next_control_key: NonZero<u64>,
}

impl State {
    pub(in crate::conn) fn new() -> Self {
        Self {
            challenges: storage::Split::new(),
            validated_tokens: storage::Vec::new(),
            response_controls: storage::Split::new(),
            retirements: storage::Split::new(),
            retired: 0,
            flags: Flags::new(),
            next_control_key: NonZero::<u64>::MIN,
        }
    }

    fn key(next: NonZero<u64>) -> Option<(path::ControlKey, NonZero<u64>)> {
        Some((path::ControlKey(next), next.checked_add(1)?))
    }

    pub(in crate::conn) fn queue<'a>(&'a mut self, control: &'a mut Set) -> Queue<'a> {
        Queue::new(self, control)
    }

    pub(in crate::conn) fn challenges<'a>(&'a mut self, control: &'a mut Set) -> Challenges<'a> {
        Challenges::new(&mut self.challenges, control)
    }

    pub(in crate::conn) fn replies<'a>(&'a mut self, control: &'a mut Set) -> Replies<'a> {
        Replies::new(self, control)
    }

    pub(in crate::conn) const fn view(&self) -> view::View<'_> {
        view::View::new(self)
    }

    /// Ready-prefix admission already installed this retirement's owner.
    pub(in crate::conn) fn ack_retire(&mut self, sequence: varint::VarInt) {
        let _ = self
            .retirements
            .select(|entry| entry.0 == sequence)
            .map(storage::Selected::take);
    }
}

const _: () = assert!(std::mem::size_of::<State>() == 272);
const _: () = assert!(std::mem::size_of::<Flags>() == 1);
