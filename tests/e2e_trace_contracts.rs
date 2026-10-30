//! A borrowed trace retains the lifetime of its original input.
//!
//! ```
//! mod common;
//! use common::e2e::trace::Trace;
//! fn retain(trace: Trace<'_>) -> Trace<'_> {
//!     trace
//! }
//! fn main() {
//!     let bytes = [0xf0];
//!     assert_eq!(retain(Trace::new(&bytes)).input(), &bytes);
//! }
//! ```
//!
//! ```compile_fail
//! mod common;
//! use common::e2e::trace::Trace;
//! fn erase(trace: Trace<'_>) -> Trace<'static> {
//!     trace
//! }
//! fn main() {}
//! ```

pub mod common;
use crate::common::e2e::trace::{
    self, Action, Difference, Direction, Driver as _, Endpoint, PathId, Receipt, Snapshot, Step,
    Trace, Value, diff, replay,
};
use common::e2e::traces::{BadInitial, BadReceipt, Fixed, PairProbe, Probe};

#[test]
fn retains_input_lifetime() {
    use std::env;

    use dope_test::checks::Suite;
    let suite = Suite::new(
        env!("CARGO_MANIFEST_DIR"),
        file!(),
        &[
            "dope-quic",
            "dope-test",
            "dope",
            "o3",
            "dope-tls",
            "rustls",
            "aws-lc-rs",
            "pin-project",
        ],
    );
    let exe = env::current_exe().expect("test executable");
    let status = suite
        .try_build(&exe, env!("CARGO_PKG_NAME"))
        .expect("build command")
        .status()
        .expect("build original library");
    assert!(status.success(), "build original library: {status}");
    let status = suite
        .try_rustdoc(&exe)
        .expect("rustdoc command")
        .status()
        .expect("compiler contracts");
    assert!(status.success(), "trace input lifetime contracts: {status}");
}

#[test]
fn initial_state_is_checked() {
    assert!(matches!(
        Trace::new(&[]).replay(&mut BadInitial),
        trace::Execution::Failed(replay::Error::InitialInvariant { .. })
    ));
}

#[test]
fn deferred_drain_has_work() {
    let receipt = Receipt::Deferred {
        processed: 64,
        pending: [0, 0],
    };
    assert!(matches!(
        Trace::new(&[0xe0]).replay(&mut Fixed(receipt)),
        trace::Execution::Failed(replay::Error::Contract { .. })
    ));

    let receipt = Receipt::Deferred {
        processed: 64,
        pending: [1, 0],
    };
    assert!(matches!(
        Trace::new(&[0xe0]).replay(&mut Fixed(receipt)),
        trace::Execution::Complete(_)
    ));
}

#[test]
fn receipt_is_step_bound() {
    let mut driver = BadReceipt;
    assert!(matches!(
        Trace::new(&[0xf0]).replay(&mut driver),
        trace::Execution::Failed(replay::Error::Contract { step, error })
            if step.ordinal() == 0
                && step.action() == Action::Noop
                && error.action() == Action::Noop
                && error.receipt() == Receipt::Accepted
    ));
}

#[test]
fn trace_is_bounded() {
    let bytes = [0x80, 0x00, 0x91, 0x10, 0xa0, 0xb0, 0xc2, 0xe0];
    let trace = Trace::new(&bytes);
    assert_eq!(trace.steps().len(), bytes.len());
    assert_eq!(
        trace.steps().next().map(Step::action),
        Some(Action::SendDatagram {
            from: Endpoint::Client,
            sequence: 0,
        })
    );
    assert_eq!(
        trace.steps().nth(2).map(Step::action),
        Some(Action::SendDatagram {
            from: Endpoint::Server,
            sequence: 2,
        })
    );
    assert_eq!(
        trace.steps().nth(6).map(Step::action),
        Some(Action::RebindClient {
            path: PathId::new(3),
        })
    );

    let mut probe = Probe::default();
    assert!(matches!(
        trace.replay(&mut probe),
        trace::Execution::Complete(_)
    ));
    let snapshot = probe.snapshot();
    assert_eq!(probe.actions, bytes.len());
    assert_eq!(snapshot.accepted(Endpoint::Client), 1);
    assert_eq!(snapshot.accepted(Endpoint::Server), 1);
    assert_eq!(snapshot.delivered(Endpoint::Client), 1);
    assert_eq!(snapshot.delivered(Endpoint::Server), 1);
    assert_eq!(snapshot.elapsed(), 10);
    assert_eq!(snapshot.pending(Direction::ClientToServer), 0);
}

#[test]
fn path_plan_is_exact() {
    let trace = Trace::new(&[0xc0, 0xc2, 0xc0, 0xcf]);
    let plan = trace.path_plan();
    assert_eq!(plan.path_count(), 4);
    assert!(plan.contains(PathId::INITIAL));
    assert!(plan.contains(PathId::new(1)));
    assert!(plan.contains(PathId::new(3)));
    assert!(plan.contains(PathId::new(16)));
    assert!(!plan.contains(PathId::new(2)));
    assert_eq!(
        plan.paths().collect::<Vec<_>>(),
        [
            PathId::INITIAL,
            PathId::new(1),
            PathId::new(3),
            PathId::new(16),
        ]
    );
}

#[test]
fn diff_receipt_is_causal() {
    let mut memory = PairProbe {
        receipt: Receipt::Empty,
        snapshot: Snapshot::default(),
    };
    let mut kernel = PairProbe {
        receipt: Receipt::Applied,
        snapshot: Snapshot::default(),
    };
    assert!(matches!(
        Trace::new(&[0xf0]).compare(&mut memory, &mut kernel),
        trace::Execution::Failed(diff::ReplayError::Replay(
            replay::Error::Driver {
                step,
                error: diff::Error::Mismatch(error),
            }
        )) if step.ordinal() == 0
            && error.step() == Some(step)
            && error.field() == Difference::Receipt
            && error.memory() == Value::Receipt(Receipt::Empty)
            && error.kernel() == Value::Receipt(Receipt::Applied)
    ));
}

#[test]
fn diff_drain_uses_state() {
    let mut memory = PairProbe {
        receipt: Receipt::Drained { datagrams: 22 },
        snapshot: Snapshot::default(),
    };
    let mut kernel = PairProbe {
        receipt: Receipt::Drained { datagrams: 23 },
        snapshot: Snapshot::default(),
    };
    assert!(matches!(
        Trace::new(&[0xe0]).compare(&mut memory, &mut kernel),
        trace::Execution::Complete(_)
    ));
}

#[test]
fn diff_uses_interpreter() {
    let input = [0x80, 0xa0, 0xf0];
    let mut memory = Probe::default();
    let mut kernel = Probe::default();
    assert!(matches!(
        Trace::new(&input).compare(&mut memory, &mut kernel),
        trace::Execution::Complete(_)
    ));
    let snapshot = memory.snapshot();
    assert_eq!(memory.actions, input.len());
    assert_eq!(kernel.actions, input.len());
    assert_eq!(snapshot.accepted(Endpoint::Client), 1);
    assert_eq!(snapshot.elapsed(), 10);
}

#[test]
fn diff_checks_initial() {
    let mut memory = PairProbe {
        receipt: Receipt::Empty,
        snapshot: Snapshot::default(),
    };
    let mut kernel = PairProbe {
        receipt: Receipt::Empty,
        snapshot: Snapshot::with_path(
            [false; 2],
            [false; 2],
            [0; 2],
            [0; 2],
            [0; 2],
            PathId::new(7),
            0,
        ),
    };
    assert!(matches!(
        Trace::new(&[]).compare(&mut memory, &mut kernel),
        trace::Execution::Failed(diff::ReplayError::Initial(error))
            if error.step().is_none()
                && error.field() == Difference::ClientPath
                && error.memory() == Value::Path(PathId::INITIAL)
                && error.kernel() == Value::Path(PathId::new(7))
    ));
}
