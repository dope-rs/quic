use crate::runtime::mux::output;
use crate::wire::packet::long::retry;
use dope::core::driver::route;
use dope::manifold::network::datagram::{self, send::owners};
use o3::buffer::{self, storage};
use std::{marker, mem, pin};

#[doc(hidden)]
pub mod brand;
pub mod embedded;
pub mod endpoint;
pub mod mux;
pub mod receive;
pub mod routing;

/// The sole output owner of one generative submission operation.
#[repr(transparent)]
pub(in crate::runtime) struct Transit<'op, T = output::Flight> {
    value: T,
    operation: marker::PhantomData<fn(&'op mut ()) -> &'op mut ()>,
}

impl Transit<'_> {
    fn scope<R, E>(
        value: output::Flight,
        submit: impl for<'op> FnOnce(Transit<'op>) -> Result<R, (Transit<'op>, E)>,
    ) -> Result<R, (output::Flight, E)> {
        submit(Transit {
            value,
            operation: marker::PhantomData,
        })
        .map_err(|(item, cause)| (item.value, cause))
    }
}

impl<'op> Transit<'op> {
    pub(in crate::runtime) fn flight(&self) -> &output::Flight {
        &self.value
    }

    pub(in crate::runtime) fn send<'d, const ID: u8, B>(
        self,
        mut socket: pin::Pin<&mut datagram::Socket<'d, route::KeyTag<ID>, endpoint::Payload<B>>>,
    ) -> Result<owners::Queued<'d, route::KeyTag<ID>>, (Self, datagram::RejectCause)>
    where
        B: buffer::Residency + buffer::raw::Source,
    {
        let Self {
            value,
            operation: brand,
        } = self;
        match value.into_kind() {
            output::Kind::Plain(addr, value) => socket
                .as_mut()
                .queue_vec(
                    Transit {
                        value,
                        operation: brand,
                    },
                    addr,
                )
                .map_err(|rejected| {
                    let (item, cause) = rejected.into_parts();
                    (
                        Self {
                            value: output::Flight::plain(addr, item.value),
                            operation: item.operation,
                        },
                        cause,
                    )
                }),
            output::Kind::Suffix(addr, value) => socket
                .as_mut()
                .queue_pooled(
                    Transit {
                        value,
                        operation: brand,
                    },
                    addr,
                )
                .map_err(|rejected| {
                    let (item, cause) = rejected.into_parts();
                    (
                        Self {
                            value: output::Flight::suffix(addr, item.value),
                            operation: item.operation,
                        },
                        cause,
                    )
                }),
            output::Kind::Batch(addr, value, size, packets) => socket
                .as_mut()
                .queue_gso(
                    Transit {
                        value,
                        operation: brand,
                    },
                    size,
                    addr,
                )
                .map_err(|rejected| {
                    let (item, cause) = rejected.into_parts();
                    (
                        Self {
                            value: output::Flight::batch(addr, item.value, size, packets),
                            operation: item.operation,
                        },
                        cause,
                    )
                }),
        }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Transit<'_, T> {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl<T: buffer::Residency> buffer::Residency for Transit<'_, T> {
    fn resident(&self) -> usize {
        self.value.resident()
    }
}

// SAFETY: socket admission consumes the original nonempty Vec only after all rejection paths.
unsafe impl buffer::raw::Convert<Vec<u8>> for Transit<'_, storage::NonEmpty<Vec<u8>>> {
    fn into(self) -> Vec<u8> {
        buffer::raw::Convert::into(self.value)
    }
}

// SAFETY: the move retains the exact Flight, allocation and projected bytes without mutation.
unsafe impl buffer::raw::Input<output::Flight> for Transit<'_> {
    fn bytes(&self) -> &[u8] {
        self.value.payload()
    }

    fn into_item(
        self,
    ) -> (
        output::Flight,
        impl for<'a> FnOnce(&'a mut output::Flight) -> &'a mut [u8],
    ) {
        (self.value, output::Flight::payload_mut)
    }
}

const _: () = {
    assert!(mem::size_of::<Transit<'_>>() == mem::size_of::<output::Flight>());
    assert!(mem::size_of::<Option<Transit<'_>>>() == mem::size_of::<Option<output::Flight>>());
    assert!(mem::size_of::<Transit<'_, storage::NonEmpty<Vec<u8>>>>() == mem::size_of::<Vec<u8>>());
    assert!(mem::size_of::<Transit<'_, retry::Suffix>>() == mem::size_of::<retry::Suffix>());
};

// SAFETY: the operation wrapper leaves the original stable byte owner unchanged.
unsafe impl<T: buffer::raw::Source> buffer::raw::Source for Transit<'_, T> {}
