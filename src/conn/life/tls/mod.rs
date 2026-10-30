use o3::mem::{Lease, lease, quota};

pub mod clients;
pub mod servers;

pub(crate) type Permit<'pool> = Lease<quota::Return<'pool>, lease::Open>;
