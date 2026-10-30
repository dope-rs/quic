/// Opaque address-validation bytes retained by one bound reconnect owner.
pub(crate) struct Token(Vec<u8>);

impl Token {
    pub(crate) fn new(wire: Vec<u8>) -> Self {
        Self(wire)
    }

    pub(crate) fn into_wire(self) -> Vec<u8> {
        self.0
    }
}
