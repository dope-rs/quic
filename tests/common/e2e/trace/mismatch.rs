use crate::common::e2e::trace;

/// First causal mismatch between an in-memory and kernel-backed adapter.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Mismatch {
    step: Option<trace::Step>,
    field: trace::Difference,
    memory: trace::Value,
    kernel: trace::Value,
}

impl Mismatch {
    pub const fn step(self) -> Option<trace::Step> {
        self.step
    }

    pub const fn field(self) -> trace::Difference {
        self.field
    }

    pub const fn memory(self) -> trace::Value {
        self.memory
    }

    pub const fn kernel(self) -> trace::Value {
        self.kernel
    }

    pub(super) fn receipt(
        step: trace::Step,
        memory: trace::Receipt,
        kernel: trace::Receipt,
    ) -> Self {
        Self {
            step: Some(step),
            field: trace::Difference::Receipt,
            memory: trace::Value::Receipt(memory),
            kernel: trace::Value::Receipt(kernel),
        }
    }

    pub(super) fn snapshot(
        step: Option<trace::Step>,
        memory: trace::Snapshot,
        kernel: trace::Snapshot,
    ) -> Option<Self> {
        let build = |field, memory, kernel| {
            Some(Self {
                step,
                field,
                memory,
                kernel,
            })
        };
        for endpoint in [trace::Endpoint::Client, trace::Endpoint::Server] {
            if memory.is_up(endpoint) != kernel.is_up(endpoint) {
                return build(
                    trace::Difference::Established(endpoint),
                    trace::Value::Boolean(memory.is_up(endpoint)),
                    trace::Value::Boolean(kernel.is_up(endpoint)),
                );
            }
            if memory.is_closed(endpoint) != kernel.is_closed(endpoint) {
                return build(
                    trace::Difference::Closed(endpoint),
                    trace::Value::Boolean(memory.is_closed(endpoint)),
                    trace::Value::Boolean(kernel.is_closed(endpoint)),
                );
            }
            if memory.accepted(endpoint) != kernel.accepted(endpoint) {
                return build(
                    trace::Difference::Accepted(endpoint),
                    trace::Value::Count(memory.accepted(endpoint)),
                    trace::Value::Count(kernel.accepted(endpoint)),
                );
            }
            if memory.delivered(endpoint) != kernel.delivered(endpoint) {
                return build(
                    trace::Difference::Delivered(endpoint),
                    trace::Value::Count(memory.delivered(endpoint)),
                    trace::Value::Count(kernel.delivered(endpoint)),
                );
            }
        }
        for dir in [
            trace::Direction::ClientToServer,
            trace::Direction::ServerToClient,
        ] {
            if memory.pending(dir) != kernel.pending(dir) {
                return build(
                    trace::Difference::Pending(dir),
                    trace::Value::Count(memory.pending(dir)),
                    trace::Value::Count(kernel.pending(dir)),
                );
            }
        }
        if memory.client_path() != kernel.client_path() {
            return build(
                trace::Difference::ClientPath,
                trace::Value::Path(memory.client_path()),
                trace::Value::Path(kernel.client_path()),
            );
        }
        if memory.elapsed() != kernel.elapsed() {
            return build(
                trace::Difference::ElapsedMillis,
                trace::Value::Millis(memory.elapsed()),
                trace::Value::Millis(kernel.elapsed()),
            );
        }
        None
    }
}
