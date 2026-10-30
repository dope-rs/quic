use crate::conn::output::control::journal::storage::Set;
use crate::conn::wire::path;
use crate::conn::wire::path::probe;

pub(in crate::conn) struct Replies<'a> {
    state: &'a mut probe::State,
    control: &'a mut Set,
}

impl<'a> Replies<'a> {
    pub(super) const fn new(state: &'a mut probe::State, control: &'a mut Set) -> Self {
        Self { state, control }
    }

    pub(in crate::conn) fn retain(&mut self) {
        self.state
            .response_controls
            .retain_ready(|reply| self.control.contains(reply.control));
    }

    pub(in crate::conn) fn try_queue(
        &mut self,
        data: [u8; 8],
        path: Option<path::Key>,
    ) -> Result<(), probe::Error> {
        if self
            .state
            .response_controls
            .iter()
            .any(|reply| reply.data == data && reply.path == path)
        {
            return Ok(());
        }
        let insert = self
            .state
            .response_controls
            .try_insert()
            .map_err(|reason| probe::Error::Capacity { data, reason })?;
        let next = self.state.next_control_key;
        let Some((key, after)) = probe::State::key(next) else {
            return Err(probe::Error::Keys { data, next });
        };
        self.state.next_control_key = after;
        insert.push(probe::Reply {
            key,
            data,
            control: None,
            path,
        });
        Ok(())
    }
}
