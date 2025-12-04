//! Security tests for double-spend prevention and authorization

#[cfg(test)]
mod tests {
    use solana_program::pubkey::Pubkey;
    use crate::constants::AUTHORIZED_RELAYER;

    #[test]
    fn test_nullifier_pda_uniqueness() {
        let program_id = Pubkey::new_unique();
        
        let nullifier_a = [1u8; 32];
        let nullifier_b = [1u8; 32];
        let nullifier_c = [2u8; 32];
        
        let (pda_a, _) = Pubkey::find_program_address(&[b"null", &nullifier_a], &program_id);
        let (pda_b, _) = Pubkey::find_program_address(&[b"null", &nullifier_b], &program_id);
        let (pda_c, _) = Pubkey::find_program_address(&[b"null", &nullifier_c], &program_id);
        
        assert_eq!(pda_a, pda_b, "Identical nullifiers must produce identical PDAs");
        assert_ne!(pda_a, pda_c, "Different nullifiers must produce different PDAs");
    }

    #[test]
    fn test_nullifier_namespace_separation() {
        let program_id = Pubkey::new_unique();
        let commitment = [42u8; 32];
        
        // Regular withdrawal nullifier
        let (regular_pda, _) = Pubkey::find_program_address(&[b"null", &commitment], &program_id);
        
        // Emergency recovery would use different seed (commitment + salt hash)
        // This test verifies they cannot collide
        let (note_pda, _) = Pubkey::find_program_address(&[b"note", &commitment], &program_id);
        
        assert_ne!(regular_pda, note_pda, "Different PDA namespaces must not collide");
    }

    #[test]
    fn test_pda_seeds_deterministic() {
        let program_id = Pubkey::new_unique();
        
        let (state_a, _) = Pubkey::find_program_address(&[b"state"], &program_id);
        let (state_b, _) = Pubkey::find_program_address(&[b"state"], &program_id);
        assert_eq!(state_a, state_b, "State PDA must be deterministic");
        
        let (pool_a, _) = Pubkey::find_program_address(&[b"pool"], &program_id);
        let (pool_b, _) = Pubkey::find_program_address(&[b"pool"], &program_id);
        assert_eq!(pool_a, pool_b, "Pool PDA must be deterministic");
        
        let (escrow_a, _) = Pubkey::find_program_address(&[b"escrow"], &program_id);
        let (escrow_b, _) = Pubkey::find_program_address(&[b"escrow"], &program_id);
        assert_eq!(escrow_a, escrow_b, "Escrow PDA must be deterministic");
    }

    #[test]
    fn test_pda_uniqueness() {
        let program_id = Pubkey::new_unique();
        
        let (state_pda, _) = Pubkey::find_program_address(&[b"state"], &program_id);
        let (pool_pda, _) = Pubkey::find_program_address(&[b"pool"], &program_id);
        let (escrow_pda, _) = Pubkey::find_program_address(&[b"escrow"], &program_id);
        
        assert_ne!(state_pda, pool_pda);
        assert_ne!(state_pda, escrow_pda);
        assert_ne!(pool_pda, escrow_pda);
    }

    #[test]
    fn test_authorized_relayer_is_set() {
        assert_eq!(
            AUTHORIZED_RELAYER,
            "8Ty6oaUGbauTp1ZwLNQ2ZCSvRXTC24waFvLD7ctiVnuv"
        );
    }

    #[test]
    fn test_note_pda_derivation() {
        let program_id = Pubkey::new_unique();
        let commitment = [123u8; 32];
        
        let (pda_a, bump_a) = Pubkey::find_program_address(&[b"note", &commitment], &program_id);
        let (pda_b, bump_b) = Pubkey::find_program_address(&[b"note", &commitment], &program_id);
        
        assert_eq!(pda_a, pda_b);
        assert_eq!(bump_a, bump_b);
    }

    #[test]
    fn test_prepared_tx_pda_derivation() {
        let program_id = Pubkey::new_unique();
        let nonce = 12345u64;
        let nonce_be = nonce.to_be_bytes();
        
        // Pad to 32 bytes as done in code
        let mut nonce_32 = [0u8; 32];
        nonce_32[24..32].copy_from_slice(&nonce_be);
        
        let (pda_a, _) = Pubkey::find_program_address(&[b"prep", &nonce_32], &program_id);
        let (pda_b, _) = Pubkey::find_program_address(&[b"prep", &nonce_32], &program_id);
        
        assert_eq!(pda_a, pda_b);
    }
}
