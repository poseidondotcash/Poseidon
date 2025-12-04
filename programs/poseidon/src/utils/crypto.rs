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
    
    // x0: bytes 32-64, reversed
    out[0..32].copy_from_slice(&g2_be_swap[32..64]);
    out[0..32].reverse();
    
    // x1: bytes 0-32, reversed
    out[32..64].copy_from_slice(&g2_be_swap[0..32]);
    out[32..64].reverse();
    
    // y0: bytes 96-128, reversed
    out[64..96].copy_from_slice(&g2_be_swap[96..128]);
    out[64..96].reverse();
    
    // y1: bytes 64-96, reversed
    out[96..128].copy_from_slice(&g2_be_swap[64..96]);
    out[96..128].reverse();
    
    out
}

pub fn sub_mod_be(a_be: &[u8; 32], b_be: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0u16;
    
    // Subtract byte-by-byte from least significant to most significant
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
    
    // If we borrowed, add the prime to correct underflow
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

/// Negates a G1 point by negating its y-coordinate
///
/// For BN254, point negation is simply: (x, y) -> (x, p - y)
///
/// # Arguments
/// * `g1_be` - 64-byte G1 point (x || y) in big-endian
///
/// # Returns
/// Negated G1 point in big-endian
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

/// # Arguments
/// * `value` - 32-byte big-endian array to validate
/// 
/// # Returns
/// * `true` if value < BN254_P, `false` otherwise
pub fn is_less_than_bn254_p(value: &[u8; 32]) -> bool {
    // Compare byte-by-byte from most significant to least significant
    for i in 0..32 {
        if value[i] < BN254_P_BE[i] {
            return true;  // Found first byte that's smaller
        } else if value[i] > BN254_P_BE[i] {
            return false; // Found first byte that's larger
        }
        // If equal, continue to next byte
    }
    // All bytes equal means value == BN254_P, which is invalid
    false
}
