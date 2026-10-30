use crate::security::crypto::op;

pub trait Boundary {}

impl Boundary for op::Open {}
impl Boundary for op::Seal {}
