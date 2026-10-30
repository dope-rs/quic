pub mod dispatch;
pub mod install;
pub mod output;
pub mod paths;
pub mod pinned;
mod reject;
pub mod retry;

pub use reject::Reject;

use dope_quic::runtime::mux::handler::{
    self,
    hook::{life::create, set},
};
use o3::buffer::storage;

pub struct Ignore;

impl handler::Handler<0, Vec<u8>, storage::Shared> for Ignore {
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set;
}
