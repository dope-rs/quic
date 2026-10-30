use crate::runtime::mux::handler::hook::{life::closing, set};

pub trait Boundary {}

impl Boundary for set::On {}
impl Boundary for set::Off {}
impl Boundary for closing::On {}
impl Boundary for closing::Off {}
