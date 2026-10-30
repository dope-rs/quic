use crate::wire::varint;

pub(in crate::conn) struct Room(usize);

impl Room {
    pub(in crate::conn) const fn new(bytes: usize) -> Self {
        Self(bytes)
    }

    pub(in crate::conn) fn limit(self, offset: u64) -> usize {
        let fixed = 1 + varint::VarInt::width(offset as usize);
        let mut data = self.0.saturating_sub(fixed + 1);
        loop {
            let next = self.0.saturating_sub(fixed + varint::VarInt::width(data));
            if next >= data {
                return data;
            }
            data = next;
        }
    }
}
