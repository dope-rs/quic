use crate::common::e2e::trace::{self, Action, Receipt, Snapshot, Step};

#[derive(Debug)]
pub enum Error {
    Ordinal { expected: usize, actual: usize },
    Action(Action),
}

#[derive(Default)]
pub struct Probe {
    pub actions: usize,
    accepted: [u16; 2],
    delivered: [u16; 2],
    elapsed: u64,
}

impl trace::Driver for Probe {
    type Error = Error;

    fn apply(&mut self, step: Step) -> trace::Transition<Self::Error> {
        if step.ordinal() != self.actions {
            return trace::Transition::Failed(Error::Ordinal {
                expected: self.actions,
                actual: step.ordinal(),
            });
        }
        self.actions += 1;
        let action = step.action();
        let receipt = match action {
            Action::SendDatagram { from, .. } => {
                self.accepted[from.index()] += 1;
                Receipt::Accepted
            }
            Action::Deliver(dir) => {
                let dst = dir.destination();
                let ready = self.accepted[dir.source().index()];
                self.delivered[dst.index()] = ready;
                if ready == 0 {
                    Receipt::Empty
                } else {
                    Receipt::Delivered { datagrams: ready }
                }
            }
            Action::Advance { millis } => {
                self.elapsed += u64::from(millis);
                if millis == 0 {
                    Receipt::Empty
                } else {
                    Receipt::Applied
                }
            }
            Action::RebindClient { .. } => Receipt::Applied,
            Action::Drop(_)
            | Action::Duplicate(_)
            | Action::Reorder(_)
            | Action::Drain
            | Action::Noop => Receipt::Empty,
            Action::KeyUpdate(_) | Action::Close(_) => Receipt::Applied,
        };
        trace::Transition::Applied(receipt)
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot::new(
            [true, true],
            [false, false],
            self.accepted,
            self.delivered,
            [0, 0],
            self.elapsed,
        )
    }
}

pub struct BadReceipt;

impl trace::Driver for BadReceipt {
    type Error = Error;

    fn apply(&mut self, step: Step) -> trace::Transition<Self::Error> {
        match step.action() {
            Action::Noop => trace::Transition::Applied(Receipt::Accepted),
            action => trace::Transition::Failed(Error::Action(action)),
        }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot::default()
    }
}

pub struct Fixed(pub Receipt);

impl trace::Driver for Fixed {
    type Error = Error;

    fn apply(&mut self, step: Step) -> trace::Transition<Self::Error> {
        match step.action() {
            Action::Drain => trace::Transition::Applied(self.0),
            action => trace::Transition::Failed(Error::Action(action)),
        }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot::default()
    }
}

pub struct BadInitial;

impl trace::Driver for BadInitial {
    type Error = Error;

    fn apply(&mut self, step: Step) -> trace::Transition<Self::Error> {
        match step.ordinal() {
            0 => trace::Transition::Applied(Receipt::Empty),
            actual => trace::Transition::Failed(Error::Ordinal {
                expected: 0,
                actual,
            }),
        }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot::new([false; 2], [false; 2], [0; 2], [1, 0], [0; 2], 0)
    }
}

pub struct PairProbe {
    pub receipt: Receipt,
    pub snapshot: Snapshot,
}

impl trace::Driver for PairProbe {
    type Error = Error;

    fn apply(&mut self, step: Step) -> trace::Transition<Self::Error> {
        match step.action() {
            Action::Noop | Action::Drain => trace::Transition::Applied(self.receipt),
            action => trace::Transition::Failed(Error::Action(action)),
        }
    }

    fn snapshot(&self) -> Snapshot {
        self.snapshot
    }
}
