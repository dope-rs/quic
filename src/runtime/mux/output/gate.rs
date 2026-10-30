#[repr(transparent)]
pub(in crate::runtime) struct Gate(bool);

impl Gate {
    pub(in crate::runtime) const fn new() -> Self {
        Self(false)
    }

    pub(in crate::runtime) fn open(&mut self) {
        self.0 = false;
    }

    pub(in crate::runtime) fn block(&mut self) {
        self.0 = true;
    }

    pub(in crate::runtime) const fn is_open(&self) -> bool {
        !self.0
    }
}
