use dope::core::driver::schedule::ready;

use crate::runtime::mux::builder;

mod plan;

pub use plan::Plan;

#[derive(Debug)]
pub enum BindError {
    Mux(builder::Failure),
    Ready(ready::Capacity),
}

#[derive(Debug)]
pub enum BindFailure<E> {
    Application(E),
    Endpoint(BindError),
}
