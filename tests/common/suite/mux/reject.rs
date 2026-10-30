use crate::common::suite::mux::install::Counter;
use dope_quic::conn::id;
use dope_quic::runtime::mux::handler::{
    self,
    hook::{
        life::{close, create},
        wire::cert,
    },
};
use o3::buffer::storage;

pub struct Reject {
    pub attempts: Vec<id::Handle>,
    pub closed: Vec<(id::Handle, Vec<u8>)>,
    pub certificates: usize,
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Reject {
    type Connection = Vec<u8>;
    type Create = Self;
    type Events = <Counter as handler::Handler<0, Vec<u8>, storage::Shared>>::Events;
}

impl create::Mode<Self, 0, Vec<u8>, storage::Shared, id::Static> for Reject {
    fn create(
        event: create::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>,
    ) -> create::Decision<Vec<u8>> {
        let (this, _, handle) = event.into_parts();
        let this = this.get_mut();
        this.attempts.push(handle);
        if this.attempts.len() == 1 {
            create::Decision::Reject
        } else {
            create::Decision::Install(b"connection".to_vec())
        }
    }
}

impl close::Sink<0, Vec<u8>, storage::Shared, id::Static> for Reject {
    fn close(event: close::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, app, handle) = event.into_parts();
        this.get_mut().closed.push((handle, app));
    }
}

impl cert::Sink<0, id::Static> for Reject {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (this, _, _, _) = event.into_parts();
        this.get_mut().certificates += 1;
    }
}
