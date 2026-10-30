use crate::common::e2e::trace;

pub struct Steps<'input> {
    input: &'input [u8],
    ordinal: usize,
}

impl Steps<'_> {
    pub(super) const fn new(input: &[u8]) -> Steps<'_> {
        let len = if input.len() < trace::MAX_STEPS {
            input.len()
        } else {
            trace::MAX_STEPS
        };
        let input = input.split_at(len).0;
        Steps { input, ordinal: 0 }
    }
}

impl Iterator for Steps<'_> {
    type Item = trace::Step;

    fn next(&mut self) -> Option<Self::Item> {
        let (&byte, input) = self.input.split_first()?;
        self.input = input;
        let ordinal = self.ordinal;
        self.ordinal += 1;
        let operand = u16::from(byte & 0x0f);
        let action = match byte {
            0x00..=0x0f => trace::Action::Deliver(trace::Direction::ClientToServer),
            0x10..=0x1f => trace::Action::Deliver(trace::Direction::ServerToClient),
            0x20..=0x2f => trace::Action::Drop(trace::Direction::ClientToServer),
            0x30..=0x3f => trace::Action::Drop(trace::Direction::ServerToClient),
            0x40..=0x4f => trace::Action::Duplicate(trace::Direction::ClientToServer),
            0x50..=0x5f => trace::Action::Duplicate(trace::Direction::ServerToClient),
            0x60..=0x6f => trace::Action::Reorder(trace::Direction::ClientToServer),
            0x70..=0x7f => trace::Action::Reorder(trace::Direction::ServerToClient),
            0x80..=0x8f => trace::Action::SendDatagram {
                from: trace::Endpoint::Client,
                sequence: ordinal as u16,
            },
            0x90..=0x9f => trace::Action::SendDatagram {
                from: trace::Endpoint::Server,
                sequence: ordinal as u16,
            },
            0xa0..=0xaf => trace::Action::Advance {
                millis: (operand + 1) * 10,
            },
            0xb0..=0xbf => trace::Action::KeyUpdate(if operand & 1 == 0 {
                trace::Endpoint::Client
            } else {
                trace::Endpoint::Server
            }),
            0xc0..=0xcf => trace::Action::RebindClient {
                path: trace::PathId::new(operand + 1),
            },
            0xd0..=0xdf => trace::Action::Close(if operand & 1 == 0 {
                trace::Endpoint::Client
            } else {
                trace::Endpoint::Server
            }),
            0xe0..=0xef => trace::Action::Drain,
            0xf0..=0xff => trace::Action::Noop,
        };
        Some(trace::Step::new(ordinal, action))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.input.len();
        (left, Some(left))
    }
}

impl ExactSizeIterator for Steps<'_> {}

const _: () = {
    assert!(trace::MAX_STEPS <= u16::MAX as usize);
    assert!(std::mem::size_of::<Steps<'static>>() == 3 * std::mem::size_of::<usize>());
};
