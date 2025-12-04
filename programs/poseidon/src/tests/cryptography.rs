//! Cryptographic primitive tests

#[cfg(test)]
mod tests {
    use crate::utils::crypto::*;
    use crate::constants::BN254_P_BE;

    #[test]
    fn test_field_validation_zero() {
        let zero = [0u8; 32];
        assert!(is_less_than_bn254_p(&zero));
    }

    #[test]
    fn test_field_validation_max_valid() {
        let mut max_valid = BN254_P_BE;
        max_valid[31] = max_valid[31].wrapping_sub(1);
        assert!(is_less_than_bn254_p(&max_valid));
    }

    #[test]
    fn test_field_validation_modulus_invalid() {
        assert!(!is_less_than_bn254_p(&BN254_P_BE));
    }

    #[test]
    fn test_field_validation_above_modulus_invalid() {
        let mut above = BN254_P_BE;
        above[31] = above[31].wrapping_add(1);
        assert!(!is_less_than_bn254_p(&above));
    }

    #[test]
    fn test_modular_subtraction_no_borrow() {
        let a = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10u8];
        let b = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3u8];
        
        let result = sub_mod_be(&a, &b);
        assert_eq!(result[31], 7);
    }

    #[test]
    fn test_modular_subtraction_with_borrow() {
        let a = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3u8];
        let b = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10u8];
        
        let result = sub_mod_be(&a, &b);
        // 3 - 10 = -7, which wraps to p - 7
        // Result should not be zero or small value
        assert_ne!(result[31], 0);
    }

    #[test]
    fn test_g1_point_negation() {
        let point = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  // x = 1
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,  // y = 2
        ];
        
        let negated = g1_negate_be(point);
        
        // x coordinate should remain same
        assert_eq!(negated[31], 1);
        
        // y coordinate should be negated (p - y)
        assert_ne!(negated[63], 2);
    }

    #[test]
    fn test_flip_chunks_identity() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        
        let flipped = flip_chunks_32::<32>(&data);
        let double_flip = flip_chunks_32::<32>(&flipped);
        
        assert_eq!(data, double_flip, "Double flip should be identity");
    }

    #[test]
    fn test_g1_conversion_roundtrip() {
        let original = [1u8; 64];
        let le = g1_be_to_le(original);
        let back = g1_be_to_le(le);
        assert_eq!(original, back);
    }
}
