use o3::{alloc, depot::queue::pool};

use crate::conn::stream::resident;
use crate::conn::stream::state::transmit::queue;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Build {
    Origin(resident::Exhausted),
    Resident(alloc::Error),
    SendPlan(pool::Error),
    Send(alloc::Error),
    Schedule(alloc::Error),
    Receive(alloc::Error),
    Closed(alloc::Error),
    Events(alloc::Error),
}

impl From<queue::Error> for Build {
    fn from(error: queue::Error) -> Self {
        match error {
            queue::Error::Plan(error) => Self::SendPlan(error),
            queue::Error::Alloc(error) => Self::Send(error),
        }
    }
}
