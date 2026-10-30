use std::mem;

use o3::buffer::resident;

use crate::conn::id;
use crate::runtime::mux::{app, handler};

const _: () = {
    assert!(mem::size_of::<app::Readiness>() == 1);
    assert!(mem::size_of::<Option<id::Handle>>() == mem::size_of::<id::Handle>());
    assert!(
        mem::size_of::<
            app::Connection<'static, (), 0, Vec<u8>, resident::Shared<'static>, id::Static>,
        >() == mem::size_of::<id::Handle>()
            + mem::size_of::<handler::Slot<'static, (), 0, Vec<u8>, resident::Shared<'static>>>()
    );
    assert!(
        mem::align_of::<
            app::Connection<'static, (), 0, Vec<u8>, resident::Shared<'static>, id::Static>,
        >() == mem::align_of::<(id::Handle, *mut (), *mut ())>()
    );
    assert!(!mem::needs_drop::<
        app::Connection<'static, (), 0, Vec<u8>, resident::Shared<'static>, id::Static>,
    >());
};
