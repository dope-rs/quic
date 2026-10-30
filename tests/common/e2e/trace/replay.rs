use crate::common::e2e::trace;

/// Exact failure while replaying a trace.
pub enum Error<E> {
    InitialInvariant {
        error: trace::Violation,
    },
    Driver {
        step: trace::Step,
        error: E,
    },
    Contract {
        step: trace::Step,
        error: trace::Contract,
    },
    Invariant {
        step: trace::Step,
        error: trace::Violation,
    },
}
