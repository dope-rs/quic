#[derive(Default)]
pub(in crate::runtime::mux) struct Cursor(usize);

impl Cursor {
    pub(super) fn reset(&mut self) {
        self.0 = 0;
    }

    pub(super) fn advance(&mut self, len: usize) -> Option<usize> {
        if self.0 >= len {
            return None;
        }
        let index = self.0;
        self.0 += 1;
        Some(index)
    }

    pub(in crate::runtime::mux) fn is_complete(&self, len: usize) -> bool {
        self.0 == len
    }
}
