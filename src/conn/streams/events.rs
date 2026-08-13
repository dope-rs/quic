use crate::conn::stream;

use crate::conn::streams;

pub(in crate::conn) trait Events {
    fn poll_event(&mut self) -> Option<stream::Event>;
    fn has_events(&self) -> bool;
}

impl<B: crate::stream::ReceiveBuffer> Events for streams::Streams<B> {
    fn poll_event(&mut self) -> Option<stream::Event> {
        let popped = self.events.pop()?;
        if let Some(handle) = popped.receive_owner()
            && let Some(position) = self.receive.map.position_mut(handle)
        {
            position.clear();
        }
        if let Some(handle) = popped.send_owner()
            && let Some((_, entry)) = self.transmit.map.resolve_mut(handle)
        {
            entry.clear_stop_event_pending();
        }
        Some(popped.event)
    }

    fn has_events(&self) -> bool {
        !self.events.is_empty()
    }
}
