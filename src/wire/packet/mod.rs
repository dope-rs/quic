pub mod cid;
pub mod decode;
pub mod encode;
pub mod header;
pub mod kind;
pub mod long;
pub mod short;
pub mod version;

pub const FORM_LONG: u8 = 0x80;
pub const FIXED_BIT: u8 = 0x40;
pub const LONG_TYPE_MASK: u8 = 0x30;
pub const LONG_INITIAL: u8 = 0x00;
pub const LONG_ZERO_RTT: u8 = 0x10;
pub const LONG_HANDSHAKE: u8 = 0x20;
pub const LONG_RETRY: u8 = 0x30;

pub const QUIC_V1: u32 = 0x0000_0001;
pub const MAX_CONNECTION_ID_LEN: usize = 20;
pub(crate) const TAG_LEN: usize = 16;

#[derive(Clone)]
struct Ids<'wire> {
    input: &'wire [u8],
    dcid: cid::Span,
    scid: cid::Span,
}

fn take_id(input: &[u8], at: u8) -> Result<(cid::Span, u8), decode::Error> {
    let at = usize::from(at);
    let start = at + 1;
    let Some(&size) = input.get(at) else {
        return Err(decode::Error::Underflow {
            actual: input.len(),
            required: start,
        });
    };
    let len = match cid::Len::try_from(size) {
        Ok(len) => len,
        Err(error) => return Err(decode::Error::Cid(error)),
    };
    let end = start + usize::from(len.get());
    if end > input.len() {
        return Err(decode::Error::Underflow {
            actual: input.len(),
            required: end,
        });
    }
    Ok((cid::Span::new(start as u8, len), end as u8))
}

impl<'wire> Ids<'wire> {
    fn decode(input: &'wire [u8]) -> Result<Self, decode::Error> {
        let (dcid, pos) = take_id(input, 5)?;
        let (scid, _) = take_id(input, pos)?;
        Ok(Self { input, dcid, scid })
    }

    fn end(&self) -> usize {
        self.scid.range().end
    }

    fn dcid(&self) -> cid::Ref<'wire> {
        // SAFETY: decode admitted this span in the retained immutable input.
        unsafe { self.dcid.get(self.input) }
    }

    fn scid(&self) -> cid::Ref<'wire> {
        // SAFETY: decode admitted this span in the retained immutable input.
        unsafe { self.scid.get(self.input) }
    }

    fn trailer<const N: usize>(&self) -> Option<(&'wire [u8], &'wire [u8], &'wire [u8; N])> {
        // SAFETY: decoding both IDs admitted end within this exact input.
        let tail = unsafe { self.input.get_unchecked(self.end()..) };
        let (body, tag) = tail.split_last_chunk::<N>()?;
        // SAFETY: tail belongs to the retained input and contains the N-byte
        // trailer, so removing that trailer also fits the complete input.
        let head = unsafe { self.input.get_unchecked(..self.input.len() - N) };
        Some((head, body, tag))
    }
}

const _: () = assert!(5 + 2 * (1 + MAX_CONNECTION_ID_LEN) <= u8::MAX as usize);
