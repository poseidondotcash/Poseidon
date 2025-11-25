use crate::constants::BN254_P_BE;
#[inline]
pub fn flip_chunks_32<const N: usize>(src: &[u8; N]) -> [u8; N] {
    let mut out = *src;
    for i in (0..N).step_by(32) {
        out[i..i + 32].reverse();
    }
    out
}
#[inline]
pub fn g1_be_to_le(g1_be: [u8; 64]) -> [u8; 64] {
    flip_chunks_32::<64>(&g1_be)
}
#[inline]
pub fn g2_be_swap_to_le_noswap(g2_be_swap: [u8; 128]) -> [u8; 128] {
    let mut out = [0u8; 128];
    
    out[0..32].copy_from_slice(&g2_be_swap[32..64]);
    out[0..32].reverse();
    
    out[32..64].copy_from_slice(&g2_be_swap[0..32]);
    out[32..64].reverse();
    
    out[64..96].copy_from_slice(&g2_be_swap[96..128]);
    out[64..96].reverse();
    
    out[96..128].copy_from_slice(&g2_be_swap[64..96]);
    out[96..128].reverse();
    
    out
}
pub fn sub_mod_be(a_be: &[u8; 32], b_be: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0u16;
    
    for i in (0..32).rev() {
        let ai = a_be[i] as u16;
        let bi = b_be[i] as u16 + borrow;
        
        if ai >= bi {
            out[i] = (ai - bi) as u8;
            borrow = 0;
        } else {
            out[i] = (ai + 256 - bi) as u8;
            borrow = 1;
        }
    }
    
    if borrow == 1 {
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let sum = out[i] as u16 + BN254_P_BE[i] as u16 + carry;
            out[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
    }
    
    out
}

pub fn g1_negate_be(g1_be: [u8; 64]) -> [u8; 64] {
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    
    x.copy_from_slice(&g1_be[0..32]);
    y.copy_from_slice(&g1_be[32..64]);
    
    let y_neg = sub_mod_be(&BN254_P_BE, &y);
    
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&x);
    out[32..64].copy_from_slice(&y_neg);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sub_mod_simple() {
        // Test simple case: 5 - 3 = 2
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 5;
        b[31] = 3;
        
        let result = sub_mod_be(&a, &b);
        assert_eq!(result[31], 2);
    }

    #[test]
    fn test_sub_mod_underflow() {
        // Test underflow: 3 - 5 should wrap around modulo prime
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 3;
        b[31] = 5;
        
        let result = sub_mod_be(&a, &b);
        // Result should be (prime - 2)
        assert_eq!(result[31], BN254_P_BE[31].wrapping_sub(2));
    }
}
