/// Connection-created allocation eligible for send-cache recycling.
#[doc(hidden)]
pub struct Copied(Vec<u8>);

impl Copied {
    pub(in crate::stream) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(in crate::stream) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub(in crate::stream) fn resident(&self) -> usize {
        self.0.capacity()
    }

    pub(in crate::stream) fn into_vec(self) -> Vec<u8> {
        self.0
    }
}
