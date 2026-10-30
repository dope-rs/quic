use crate::wire::varint::Decoded;

/// Replays one previously admitted integer.
///
/// # Safety
/// A prior parse must prove these unchanged bytes contain a first byte and its entire wire width.
pub(in crate::wire) unsafe fn replay(input: &[u8]) -> Decoded<'_> {
    // SAFETY: the caller retains the previous parse's exact byte extent.
    let first = unsafe { *input.get_unchecked(0) };
    // SAFETY: admission proved the complete width selected by this first byte.
    unsafe {
        match first >> 6 {
            0 => read::<1>(input),
            1 => read::<2>(input),
            2 => read::<4>(input),
            _ => read::<8>(input),
        }
    }
}

/// # Safety
/// The unchanged input contains the admitted N-byte integer prefix.
unsafe fn read<const N: usize>(input: &[u8]) -> Decoded<'_> {
    // SAFETY: the caller retains the full prefix. Byte arrays need no extra
    // alignment, and the original immutable loan retains both resulting views.
    let (bytes, rest) = unsafe { (&*input.as_ptr().cast::<[u8; N]>(), input.get_unchecked(N..)) };
    Decoded::from_parts(bytes, rest)
}
