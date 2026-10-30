use crate::common::e2e::trace;

/// Environment-neutral result of one successfully executed action.
#[must_use = "the trace contract must validate every transition receipt"]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Receipt {
    Applied,
    Empty,
    Accepted,
    Rejected(trace::Rejection),
    OperationRejected(trace::Refusal),
    Unavailable(trace::AccessFault),
    Delivered { datagrams: u16 },
    Dropped { datagrams: u16 },
    Drained { datagrams: u16 },
    Deferred { processed: u16, pending: [u16; 2] },
}

impl Receipt {
    pub(super) fn is_valid(self, action: trace::Action) -> bool {
        match action {
            trace::Action::Deliver(_) | trace::Action::Duplicate(_) => matches!(
                self,
                Self::Empty | Self::Delivered { datagrams: 1.. } | Self::Dropped { datagrams: 1.. }
            ),
            trace::Action::Drop(_) => {
                matches!(self, Self::Empty | Self::Dropped { datagrams: 1.. })
            }
            trace::Action::Reorder(_)
            | trace::Action::Advance { .. }
            | trace::Action::RebindClient { .. } => matches!(self, Self::Applied | Self::Empty),
            trace::Action::SendDatagram { .. } => match self {
                Self::Rejected(trace::Rejection::Admission(cause)) => match cause {
                    trace::Admission::Crypto { needed, .. } => needed == 1,
                    trace::Admission::Packet {
                        space,
                        number,
                        controls,
                        streams,
                        ..
                    } => {
                        space <= 2
                            && number <= 0x3fff_ffff_ffff_ffff
                            && controls <= 16
                            && streams <= 16
                    }
                    trace::Admission::Stream { records, .. } => (1..=16).contains(&records),
                },
                Self::Accepted | Self::Rejected(_) => true,
                _ => false,
            },
            trace::Action::KeyUpdate(_) => matches!(
                self,
                Self::Applied
                    | Self::OperationRejected(_)
                    | Self::Unavailable(trace::AccessFault::Closed)
            ),
            trace::Action::Close(_) => {
                matches!(
                    self,
                    Self::Applied | Self::Unavailable(trace::AccessFault::Closed)
                )
            }
            trace::Action::Drain => match self {
                Self::Empty | Self::Drained { datagrams: 1.. } => true,
                Self::Deferred {
                    processed: done,
                    pending,
                } => done != 0 && pending != [0, 0],
                _ => false,
            },
            trace::Action::Noop => matches!(self, Self::Empty),
        }
    }

    /// Compares causal outcomes, ignoring drain packet counts that snapshots audit.
    pub(super) fn is_equiv(self, action: trace::Action, other: Self) -> bool {
        if self == other {
            return true;
        }
        if action != trace::Action::Drain {
            return false;
        }
        match (self, other) {
            (Self::Drained { datagrams: 1.. }, Self::Drained { datagrams: 1.. }) => true,
            (
                Self::Deferred {
                    processed: left,
                    pending: before,
                },
                Self::Deferred {
                    processed: right,
                    pending: after,
                },
            ) => left != 0 && right != 0 && before != [0, 0] && after != [0, 0],
            _ => false,
        }
    }
}
