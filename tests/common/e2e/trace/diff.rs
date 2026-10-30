use crate::common::e2e::trace::{self, replay};

/// Allocation-free lockstep driver over two borrowed adapters.
pub(super) struct Pair<'driver, M, K> {
    memory: &'driver mut M,
    kernel: &'driver mut K,
    snapshot: trace::Snapshot,
}

/// Failure while applying one step to a pair.
pub enum Error<M, K> {
    Memory(M),
    Kernel { memory: trace::Receipt, error: K },
    Mismatch(trace::Mismatch),
}

/// Failure while replaying a trace against a pair.
pub enum ReplayError<M, K> {
    Initial(trace::Mismatch),
    Replay(replay::Error<Error<M, K>>),
}

impl<'driver, M: trace::Driver, K: trace::Driver> Pair<'driver, M, K> {
    pub(super) fn new(
        memory: &'driver mut M,
        kernel: &'driver mut K,
        snapshot: trace::Snapshot,
    ) -> Self {
        Self {
            memory,
            kernel,
            snapshot,
        }
    }
}

impl<M: trace::Driver, K: trace::Driver> trace::Driver for Pair<'_, M, K> {
    type Error = Error<M::Error, K::Error>;

    fn apply(&mut self, step: trace::Step) -> trace::Transition<Self::Error> {
        let memory = match self.memory.apply(step) {
            trace::Transition::Applied(receipt) => receipt,
            trace::Transition::Failed(error) => {
                return trace::Transition::Failed(Error::Memory(error));
            }
        };
        let kernel = match self.kernel.apply(step) {
            trace::Transition::Applied(receipt) => receipt,
            trace::Transition::Failed(error) => {
                return trace::Transition::Failed(Error::Kernel { memory, error });
            }
        };
        if !memory.is_equiv(step.action(), kernel) {
            return trace::Transition::Failed(Error::Mismatch(trace::Mismatch::receipt(
                step, memory, kernel,
            )));
        }
        let snapshot = self.memory.snapshot();
        if let Some(error) = trace::Mismatch::snapshot(Some(step), snapshot, self.kernel.snapshot())
        {
            return trace::Transition::Failed(Error::Mismatch(error));
        }
        self.snapshot = snapshot;
        trace::Transition::Applied(memory)
    }

    fn snapshot(&self) -> trace::Snapshot {
        self.snapshot
    }
}
