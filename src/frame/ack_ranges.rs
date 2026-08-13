use crate::varint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranges<'a> {
    input: &'a [u8],
    remaining: usize,
}

impl<'a> Ranges<'a> {
    pub(crate) fn new(input: &'a [u8], remaining: usize) -> Self {
        Self { input, remaining }
    }
}

impl Iterator for Ranges<'_> {
    type Item = (varint::VarInt, varint::VarInt);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let Ok((gap, gap_len)) = varint::VarInt::decode(self.input) else {
            self.remaining = 0;
            return None;
        };
        let input = &self.input[gap_len..];
        let Ok((range, range_len)) = varint::VarInt::decode(input) else {
            self.remaining = 0;
            return None;
        };
        self.input = &input[range_len..];
        self.remaining -= 1;
        Some((gap, range))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for Ranges<'_> {}
