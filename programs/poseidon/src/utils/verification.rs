use anchor_lang::prelude::*;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use crate::vk::{VK_ALPHA_G1, VK_BETA_G2, VK_DELTA_G2, VK_GAMME_G2, VK_IC, VK_NR_PUBINPUTS};
use crate::crypto::{g1_be_to_le, g1_negate_be, g2_be_swap_to_le_noswap, flip_chunks_32};
use crate::errors::ErrorCode;
pub fn load_vk_le() -> Groth16Verifyingkey<'static> {
    let ic_le: Vec<[u8; 64]> = VK_IC
        .iter()
        .map(|p| g1_be_to_le(*p))
        .collect();
    
    let boxed = ic_le.into_boxed_slice();
    
    Groth16Verifyingkey {
        nr_pubinputs: VK_NR_PUBINPUTS,
        vk_alpha_g1: g1_be_to_le(VK_ALPHA_G1),
        vk_beta_g2: g2_be_swap_to_le_noswap(VK_BETA_G2),
        vk_gamme_g2: g2_be_swap_to_le_noswap(VK_GAMME_G2),
        vk_delta_g2: g2_be_swap_to_le_noswap(VK_DELTA_G2),
        vk_ic: Box::leak(boxed),
    }
}

pub fn verify_groth16<const N: usize>(
    a_be: &[u8; 64],
    b_be_swap: &[u8; 128],
    c_be: &[u8; 64],
    public_inputs_be: &[[u8; 32]; N],
) -> Result<()> {
    let a_be_neg = g1_negate_be(*a_be);
    let a_le = g1_be_to_le(a_be_neg);
    let b_le = g2_be_swap_to_le_noswap(*b_be_swap);
    let c_le = g1_be_to_le(*c_be);

    let vk = load_vk_le();

    let mut pub_inputs_le: [[u8; 32]; N] = [[0u8; 32]; N];
    for i in 0..N {
        pub_inputs_le[i] = flip_chunks_32::<32>(&public_inputs_be[i]);
    }

    Groth16Verifier::<N>::new(&a_le, &b_le, &c_le, &pub_inputs_le, &vk)
        .map_err(|_| error!(ErrorCode::InvalidProof))?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_vk() {
        let vk = load_vk_le();
        assert_eq!(vk.nr_pubinputs, VK_NR_PUBINPUTS);
        assert_eq!(vk.vk_ic.len(), VK_IC.len());
    }

    #[test]
    fn test_vk_alpha_conversion() {
        let vk = load_vk_le();
        // Alpha should be 64 bytes (G1 point)
        assert_eq!(vk.vk_alpha_g1.len(), 64);
    }

    #[test]
    fn test_vk_beta_conversion() {
        let vk = load_vk_le();
        // Beta should be 128 bytes (G2 point)
        assert_eq!(vk.vk_beta_g2.len(), 128);
    }
}
