use dope::core::driver::schedule::clock;
use dope_quic::client::{
    self, AttemptId, AttemptScope, ConfigSource, RetryCause, RetryScope, SlotId,
};
use dope_quic::conn::life::options::Options;
use dope_quic::conn::life::options::builder::Invalid;
use dope_quic::proto::param;
use dope_test::harness::observe::VecCellExt as _;
use std::{cell::Cell, rc::Rc, time::Duration};

#[derive(Clone, Default)]
pub struct Immediate(pub Rc<Cell<Option<(SlotId, u32)>>>);

impl client::Backoff for Immediate {
    fn retry_after<'scope>(&'scope self, retry: RetryScope<'scope>) -> Duration {
        if retry.previous_id().slot() != SlotId::from_index(0) || retry.failures() == 0 {
            self.0
                .set(Some((retry.previous_id().slot(), retry.failures())));
        }
        Duration::ZERO
    }
}

#[derive(Default)]
pub struct Observed {
    pub history: History,
    pub observed_start: Cell<bool>,
}

pub struct Config<'state>(pub &'state Observed);

impl ConfigSource for Config<'_> {
    fn config<'scope, 'd>(&'scope mut self, attempt: AttemptScope<'scope, 'd>) -> Option<Options> {
        self.0.history.attempts.push(Attempt {
            id: attempt.id(),
            ordinal: attempt.attempt(),
        });
        let _: clock::Moment<'d> = attempt.started_at();
        self.0.observed_start.set(true);
        None
    }
}

pub struct Backoff<'state>(pub &'state Observed);

impl client::Backoff for Backoff<'_> {
    fn retry_after<'scope>(&'scope self, retry: RetryScope<'scope>) -> Duration {
        self.0.history.retries.push(Transition::from(retry));
        Duration::from_secs(1)
    }
}

#[derive(Clone, Copy)]
pub struct Attempt {
    pub id: AttemptId,
    pub ordinal: u32,
}

#[derive(Clone, Copy)]
pub struct Transition {
    pub previous: AttemptId,
    pub previous_ordinal: u32,
    pub next: AttemptId,
    pub next_ordinal: u32,
    pub cause: RetryCause,
}

impl<'scope> From<RetryScope<'scope>> for Transition {
    fn from(retry: RetryScope<'scope>) -> Self {
        Self {
            previous: retry.previous_id(),
            previous_ordinal: retry.previous(),
            next: retry.next_id(),
            next_ordinal: retry.next_attempt(),
            cause: retry.cause(),
        }
    }
}

#[derive(Default)]
pub struct History {
    pub attempts: Cell<Vec<Attempt>>,
    pub retries: Cell<Vec<Transition>>,
    pub errors: Cell<Vec<Invalid>>,
}

pub struct CausalConfig<'state> {
    pub trace: &'state History,
    pub params: param::Set,
}

impl ConfigSource for CausalConfig<'_> {
    fn config<'scope, 'd>(&'scope mut self, attempt: AttemptScope<'scope, 'd>) -> Option<Options> {
        self.trace.attempts.push(Attempt {
            id: attempt.id(),
            ordinal: attempt.attempt(),
        });
        match Options::try_from(self.params.clone()) {
            Ok(options) => Some(options),
            Err(error) => {
                self.trace.errors.push(error);
                None
            }
        }
    }
}

pub struct CauseBackoff<'state>(pub &'state History);

impl client::Backoff for CauseBackoff<'_> {
    fn retry_after<'scope>(&'scope self, retry: RetryScope<'scope>) -> Duration {
        self.0.retries.push(Transition::from(retry));
        Duration::ZERO
    }
}
