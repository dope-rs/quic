pub trait Boundary {}

impl Boundary for super::Initial {}
impl Boundary for super::Handshake {}
impl Boundary for super::ZeroRtt {}
impl Boundary for super::OneRtt {}
