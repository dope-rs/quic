use std::time;

use crate::{client, runtime::brand};

pub(in crate::client::life) enum Retry {
    Dormant(Option<client::AttemptState>),
    Scheduled {
        next: client::AttemptState,
        at: time::Instant,
    },
}

impl Retry {
    pub(in crate::client::life) fn new<B: client::Backoff>(
        backoff: &B,
        enabled: bool,
        scope: brand::Token<'_>,
        slot: client::SlotId,
        previous: client::AttemptState,
        restart: bool,
        seen: time::Instant,
    ) -> Self {
        let Some(next) = previous.successor(restart) else {
            return Self::Dormant(None);
        };
        let state = next.state();
        let at = enabled.then(|| {
            let delay = backoff.retry_after(next.retry_scope(scope.reborrow(), slot, seen));
            seen.checked_add(delay)
        });
        match at.flatten() {
            Some(at) => Self::Scheduled { next: state, at },
            None => Self::Dormant(Some(state)),
        }
    }
}
