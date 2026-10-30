use crate::security::qkdf::origin;

pub trait Boundary {}

impl Boundary for origin::Client {}
impl Boundary for origin::Server {}
impl Boundary for origin::Local {}
impl Boundary for origin::Peer {}
