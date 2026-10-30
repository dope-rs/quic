use o3::buffer;

use crate::conn::output::control::{self, journal::records};
use crate::conn::stream::{State, state::streams};
use crate::stream;
use crate::wire::stream::Direction;

pub(in crate::conn) struct Drain<'a, B: stream::Recv, D: buffer::raw::Segment> {
    streams: &'a mut State<B, D>,
    control: records::Records<&'a mut control::Pending>,
    remaining: usize,
}

impl<'a, B: stream::Recv, D: buffer::raw::Segment> Drain<'a, B, D> {
    pub(in crate::conn) fn new(
        state: &'a mut State<B, D>,
        ctrl: &'a mut control::Pending,
        left: usize,
    ) -> Self {
        Self {
            streams: state,
            control: records::Records::new(ctrl),
            remaining: left,
        }
    }

    pub(in crate::conn) fn drain(self) -> Result<(), control::Admission> {
        let Self {
            streams: state,
            control: mut ctrl,
            remaining: mut left,
        } = self;
        if state.receive.map.meta().has_data() {
            if left == 0 {
                return Ok(());
            }
            ctrl.try_data(
                &mut state.receive.max_data,
                state.receive.connection_window.limit(),
            )?;
            state.receive.map.clear_data();
            left -= 1;
        }

        for dir in Direction::ALL {
            if !state.receive.map.meta().has_stream(dir) {
                continue;
            }
            if left == 0 {
                return Ok(());
            }
            let owner = dir.bind_mut(&mut state.peer_initiated.max_streams);
            ctrl.try_streams(owner, dir, *dir.bind(&state.peer_initiated.max))?;
            state.receive.map.clear_stream(dir);
            left -= 1;
        }

        let allowed = state.local_initiated.all_allowed();
        let mut work = state.receive.map.len();
        while left != 0 && work != 0 {
            work -= 1;
            let local = state.local();
            let recv = &mut state.receive;
            let Some(mut slot) = recv.map.front() else {
                break;
            };
            let id = slot.id();
            if !allowed
                && !state
                    .local_initiated
                    .allows(streams::Relative::new(id, local))
            {
                slot.move_to_back();
                continue;
            }
            if slot.has_credit() {
                let stream = streams::Relative::new(id, local);
                let base = recv.initial_stream_data.credit(stream);
                slot.try_credit(base, &mut ctrl)?;
                left -= 1;
            }

            if left != 0 && slot.try_stop(&mut ctrl)? {
                left -= 1;
            }

            if slot.has_deferred() {
                break;
            }
            slot.deactivate();
        }
        Ok(())
    }
}
