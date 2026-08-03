#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionControl {
    #[default]
    Standard,
    Uncongested,
}
