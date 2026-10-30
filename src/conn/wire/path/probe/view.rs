use crate::conn::output::{control, delivery};
use crate::conn::wire::path;
use crate::conn::wire::path::probe;

#[derive(Clone, Copy)]
pub(in crate::conn) struct View<'a> {
    state: &'a probe::State,
}

impl<'a> View<'a> {
    pub(in crate::conn) const fn retired(&self) -> u64 {
        self.state.retired
    }

    pub(in crate::conn) fn is_reset(&self) -> bool {
        self.state.flags.is_reset()
    }

    pub(in crate::conn) fn is_retry(&self) -> bool {
        self.state.flags.is_retry()
    }

    pub(in crate::conn) fn has_work(&self) -> bool {
        self.state.response_controls.has_pending()
            || self.state.retirements.has_pending()
            || self.state.challenges.has_pending()
    }

    pub(super) const fn new(state: &'a probe::State) -> Self {
        Self { state }
    }

    pub(in crate::conn) fn has_token(&self, token: &[u8; 8]) -> bool {
        self.state.validated_tokens.iter().any(|item| item == token)
    }

    pub(in crate::conn) fn control_path(&self, record: delivery::Control) -> Option<path::Key> {
        match record {
            delivery::Control::PathChallenge(key) | delivery::Control::PathValidation(key) => self
                .state
                .challenges
                .iter()
                .find(|item| item.key == key)
                .and_then(|item| item.path),
            delivery::Control::PathResponse(key) => self
                .state
                .response_controls
                .iter()
                .find(|response| response.key == key)
                .and_then(|response| response.path),
            _ => None,
        }
    }

    pub(in crate::conn) fn challenge(&self, key: path::ControlKey) -> Option<probe::Encoded> {
        self.state
            .challenges
            .ready()
            .iter()
            .enumerate()
            .find(|(_, item)| item.key == key)
            .map(|(index, item)| probe::Encoded {
                data: item.data,
                position: probe::Position(index as u8),
            })
    }

    pub(in crate::conn) fn response(&self, key: path::ControlKey) -> Option<probe::Encoded> {
        self.state
            .response_controls
            .ready()
            .iter()
            .enumerate()
            .find(|(_, response)| response.key == key)
            .map(|(index, response)| probe::Encoded {
                data: response.data,
                position: probe::Position(index as u8),
            })
    }

    pub(in crate::conn) fn has_output(&self, control: &control::Pending) -> bool {
        let ready = control.ready();
        self.state.challenges.iter().any(|item| {
            item.path.is_some() && (item.control.is_none() || ready.is_queued(item.control))
        }) || self.state.response_controls.iter().any(|response| {
            response.path.is_some()
                && (response.control.is_none() || ready.is_queued(response.control))
        })
    }

    pub(in crate::conn) fn find_path<T>(
        &self,
        control: &control::Pending,
        admit: impl FnMut(path::Key) -> Option<T>,
    ) -> Option<T> {
        let ready = control.ready();
        self.state
            .response_controls
            .iter()
            .filter_map(|response| {
                ready
                    .is_queued(response.control)
                    .then_some(response.path)
                    .flatten()
            })
            .chain(
                self.state.challenges.iter().filter_map(|item| {
                    ready.is_queued(item.control).then_some(item.path).flatten()
                }),
            )
            .find_map(admit)
    }

    pub(in crate::conn) fn has_path(&self, path: path::Key) -> bool {
        self.state
            .challenges
            .iter()
            .any(|item| item.path == Some(path))
            || self
                .state
                .response_controls
                .iter()
                .any(|response| response.path == Some(path))
    }
}
