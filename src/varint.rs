#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Underflow,
}

pub struct VarInt;

impl VarInt {
    pub const MAX: u64 = (1u64 << 62) - 1;

    pub fn size_for(value: u64) -> Result<usize, Error> {
        match value {
            0..=63 => Ok(1),
            64..=16_383 => Ok(2),
            16_384..=1_073_741_823 => Ok(4),
            v if v <= Self::MAX => Ok(8),
            _ => Err(Error::TooLarge),
        }
    }

    pub fn encode(value: u64, out: &mut Vec<u8>) -> Result<(), Error> {
        match value {
            0..=63 => out.push(value as u8),
            64..=16_383 => {
                let v = (value as u16) | 0x4000;
                out.extend_from_slice(&v.to_be_bytes());
            }
            16_384..=1_073_741_823 => {
                let v = (value as u32) | 0x8000_0000;
                out.extend_from_slice(&v.to_be_bytes());
            }
            v if v <= Self::MAX => {
                let w = v | 0xC000_0000_0000_0000;
                out.extend_from_slice(&w.to_be_bytes());
            }
            _ => return Err(Error::TooLarge),
        }
        Ok(())
    }

    pub fn decode(input: &[u8]) -> Result<(u64, usize), Error> {
        let first = *input.first().ok_or(Error::Underflow)?;
        let len = 1usize << (first >> 6);
        if input.len() < len {
            return Err(Error::Underflow);
        }
        let mut buf = [0u8; 8];
        buf[8 - len..].copy_from_slice(&input[..len]);
        let mut v = u64::from_be_bytes(buf);
        v &= (1u64 << (len * 8 - 2)) - 1;
        Ok((v, len))
    }
}
