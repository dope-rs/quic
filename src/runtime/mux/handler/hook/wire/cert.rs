use std::{net, pin};

use crate::conn::id;

/// An authentication failure borrowing the native error and consumer.
pub struct Event<'scope, 'wire, H, const DOMAIN: u8, I: id::Temporal> {
    handler: pin::Pin<&'scope mut H>,
    handle: id::Handle<I, DOMAIN>,
    from: net::SocketAddr,
    failure: &'wire rustls::Error,
}

impl<'scope, 'wire, H, const DOMAIN: u8, I: id::Temporal> Event<'scope, 'wire, H, DOMAIN, I> {
    pub(crate) fn new(
        handler: pin::Pin<&'scope mut H>,
        handle: id::Handle<I, DOMAIN>,
        from: net::SocketAddr,
        failure: &'wire rustls::Error,
    ) -> Self {
        Self {
            handler,
            handle,
            from,
            failure,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        pin::Pin<&'scope mut H>,
        id::Handle<I, DOMAIN>,
        net::SocketAddr,
        &'wire rustls::Error,
    ) {
        (self.handler, self.handle, self.from, self.failure)
    }
}

pub trait Sink<const DOMAIN: u8, I: id::Temporal>: Sized {
    fn certificate(event: Event<'_, '_, Self, DOMAIN, I>);
}
