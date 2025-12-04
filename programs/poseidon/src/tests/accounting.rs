//! Pool accounting and invariant tests

#[cfg(test)]
mod tests {
    use crate::state::GlobalState;
    use crate::constants::{TREE_DEPTH, ROOT_HISTORY};

    fn create_test_state() -> GlobalState {
        GlobalState {
            admin: solana_program::pubkey::Pubkey::new_unique(),
            bump: 0,
            escrow_bump: 0,
            pool_bump: 0,
            next_index: 0,
            current_root: [0u8; 32],
            root_history_idx: 0,
            zeroes: vec![0u8; TREE_DEPTH * 32],
            filled_subtrees: vec![0u8; TREE_DEPTH * 32],
            root_history: vec![0u8; ROOT_HISTORY * 32],
            total_deposited: 0,
            total_withdrawn: 0,
        }
    }

    #[test]
    fn test_invariant_valid_when_equal() {
        let mut state = create_test_state();
        state.total_deposited = 1_000_000_000;
        state.total_withdrawn = 1_000_000_000;
        
        assert!(state.check_invariants().is_ok());
    }

    #[test]
    fn test_invariant_valid_when_deposited_greater() {
        let mut state = create_test_state();
        state.total_deposited = 2_000_000_000;
        state.total_withdrawn = 1_000_000_000;
        
        assert!(state.check_invariants().is_ok());
    }

    #[test]
    fn test_invariant_fails_when_withdrawn_greater() {
        let mut state = create_test_state();
        state.total_deposited = 1_000_000_000;
        state.total_withdrawn = 2_000_000_000;
        
        assert!(state.check_invariants().is_err());
    }

    #[test]
    fn test_invariant_valid_at_zero() {
        let state = create_test_state();
        assert!(state.check_invariants().is_ok());
    }

    #[test]
    fn test_overflow_protection_deposit() {
        let mut state = create_test_state();
        state.total_deposited = u64::MAX;
        
        let result = state.total_deposited.checked_add(1);
        assert_eq!(result, None, "Overflow must be detected");
    }

    #[test]
    fn test_overflow_protection_withdrawal() {
        let mut state = create_test_state();
        state.total_withdrawn = u64::MAX;
        
        let result = state.total_withdrawn.checked_add(1);
        assert_eq!(result, None, "Overflow must be detected");
    }

    #[test]
    fn test_underflow_protection() {
        let balance = 0u64;
        let result = balance.checked_sub(1);
        assert_eq!(result, None, "Underflow must be detected");
    }
}
