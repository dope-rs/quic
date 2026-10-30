use o3::buffer::hold::evidence;

use crate::stream::release;

/// Evidence projection supported by stream-owner retirement.
pub trait Mode: release::Dispatch {}

impl Mode for evidence::Off {}
impl Mode for evidence::On {}
