mod error;
mod key;
pub mod op;
mod opened;
pub(crate) mod output;
mod plain;

pub trait KeyOperation: op::Boundary {}
impl KeyOperation for op::Open {}
impl KeyOperation for op::Seal {}

pub use error::{Dimensions, Error};
pub(crate) use key::Generation;
pub use key::Key;
pub use opened::Opened;
pub(crate) use plain::Plain;
