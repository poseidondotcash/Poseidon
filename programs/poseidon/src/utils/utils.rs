use anchor_lang::prelude::*;
use crate::errors::ErrorCode;
#[inline]
pub fn u64_to_be_32(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&x.to_be_bytes());
    out
}
#[inline]
pub fn pubkey_to_u64_limbs_le(pk: &Pubkey) -> [u64; 4] {
    let b = pk.to_bytes();
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&b[i * 8..(i + 1) * 8]);
        limbs[i] = u64::from_le_bytes(limb);
    }
    limbs
}

pub fn read_u32_le(input: &[u8], off: &mut usize) -> Result<u32> {
    require!(
        input.len() >= *off + 4,
        ErrorCode::MemoParseError
    );
    
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&input[*off..*off + 4]);
    *off += 4;
    
    Ok(u32::from_le_bytes(buf))
}

pub fn read_u64_le(input: &[u8], off: &mut usize) -> Result<u64> {
    require!(
        input.len() >= *off + 8,
        ErrorCode::MemoParseError
    );
    
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&input[*off..*off + 8]);
    *off += 8;
    
    Ok(u64::from_le_bytes(buf))
}

pub fn read_arr<const N: usize>(input: &[u8], off: &mut usize) -> Result<[u8; N]> {
    require!(
        input.len() >= *off + N,
        ErrorCode::MemoParseError
    );
    
    let mut out = [0u8; N];
    out.copy_from_slice(&input[*off..*off + N]);
    *off += N;
    
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64_to_be_32() {
        let result = u64_to_be_32(0x0102030405060708);
        assert_eq!(result[24..], [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(result[..24], [0u8; 24]);
    }

    #[test]
    fn test_read_u32_le() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut off = 0;
        let val = read_u32_le(&data, &mut off).unwrap();
        assert_eq!(val, 0x04030201);
        assert_eq!(off, 4);
    }

    #[test]
    fn test_read_u32_le_insufficient() {
        let data = [0x01, 0x02];
        let mut off = 0;
        assert!(read_u32_le(&data, &mut off).is_err());
    }

    #[test]
    fn test_read_arr() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut off = 2;
        let arr: [u8; 4] = read_arr(&data, &mut off).unwrap();
        assert_eq!(arr, [3, 4, 5, 6]);
        assert_eq!(off, 6);
    }
}
