use o3::depot::{self, array, index::Initialized};

use crate::conn::output::control::{self, encode::Written};
use crate::conn::wire::path::{local, probe};

#[derive(Clone, Copy)]
pub(in crate::conn) enum Sent {
    None,
    Local(array::Index<{ crate::conn::MAX_ACTIVE_CONNECTION_IDS }>),
    Challenge(probe::Position),
    Response(probe::Position),
}

impl Sent {
    /// # Safety
    /// Encoded slots stay initialized in their original stores; ready indices reflect all compactions.
    /// `rest` is the same packet's complete unread suffix of distinct selected controls.
    pub(in crate::conn) unsafe fn into(
        self,
        control: &mut control::Pending,
        local: &mut local::State,
        rest: &mut [Written],
    ) {
        match self {
            Sent::None => {}
            Sent::Local(index) => {
                unsafe { depot::raw::Proof::<_, Initialized<()>>::new((local, index)) }.into()
            }
            Sent::Challenge(index) => unsafe {
                depot::raw::Proof::<_, Initialized<probe::raw::Challenge>>::new((
                    &mut control.probe,
                    index,
                ))
            }
            .into(),
            Sent::Response(index) => {
                let moved = unsafe {
                    depot::raw::Proof::<_, Initialized<probe::raw::Response>>::new((
                        &mut control.probe,
                        index,
                    ))
                }
                .into();
                if let Some(moved) = moved {
                    for next in rest {
                        if let Sent::Response(index) = &mut next.sent {
                            moved.apply(index);
                        }
                    }
                }
            }
        }
    }
}
