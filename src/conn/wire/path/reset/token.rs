use subtle::ConstantTimeEq as _;

const LEN: usize = 16;

#[derive(Clone, Copy)]
pub(crate) struct Token([u8; LEN]);

impl Token {
    pub(crate) const LEN: usize = LEN;

    pub(crate) fn new(bytes: [u8; LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn from_tail(datagram: &[u8]) -> Option<Self> {
        if datagram.len() < LEN + 5 {
            return None;
        }
        let mut bytes = [0; LEN];
        bytes.copy_from_slice(&datagram[datagram.len() - LEN..]);
        Some(Self::new(bytes))
    }

    pub(crate) fn matches(self, other: Self) -> bool {
        bool::from(self.0[..].ct_eq(&other.0[..]))
    }
}
