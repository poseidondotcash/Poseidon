//! State structure and serialization tests

#[cfg(test)]
mod tests {
    use crate::state::{GlobalState, NoteRecord, PreparedTx, NullifierFlag, ExecutedFlag};
    use crate::constants::{TREE_DEPTH, ROOT_HISTORY};

    #[test]
    fn test_global_state_size_calculation() {
        let expected = 8  // discriminator
            + 32  // admin
            + 1   // bump
            + 1   // escrow_bump
            + 1   // pool_bump
            + 4   // next_index
            + 32  // current_root
            + 1   // root_history_idx
            + 4 + (TREE_DEPTH * 32)  // zeroes
            + 4 + (TREE_DEPTH * 32)  // filled_subtrees
            + 4 + (ROOT_HISTORY * 32)  // root_history
            + 8   // total_deposited
            + 8;  // total_withdrawn
        
        assert_eq!(GlobalState::LEN, expected);
    }

    #[test]
    fn test_note_record_size_empty_cipher() {
        let size = NoteRecord::len_for(0);
        let expected = 8   // discriminator
            + 1   // bump
            + 4   // index
            + 32  // commitment
            + 32  // depositor
            + 8   // amount
            + 4   // ciphertext length
            + 0;  // ciphertext
        
        assert_eq!(size, expected);
    }

    #[test]
    fn test_note_record_size_with_cipher() {
        let cipher_len = 128;
        let size = NoteRecord::len_for(cipher_len);
        let expected = 8 + 1 + 4 + 32 + 32 + 8 + 4 + cipher_len;
        assert_eq!(size, expected);
    }

    #[test]
    fn test_note_record_size_scaling() {
        let size_100 = NoteRecord::len_for(100);
        let size_200 = NoteRecord::len_for(200);
        
        assert_eq!(size_200 - size_100, 100);
    }

    #[test]
    fn test_prepared_tx_size() {
        let expected = 8   // discriminator
            + 1   // bump
            + 1   // executed
            + 8   // nonce
            + 32  // recipient
            + 32  // relayer
            + 8   // to_recipient
            + 8;  // to_relayer
        
        assert_eq!(PreparedTx::LEN, expected);
        assert_eq!(PreparedTx::LEN, 98);
    }

    #[test]
    fn test_nullifier_flag_size() {
        let expected = 8 + 1;  // discriminator + bump
        assert_eq!(NullifierFlag::LEN, expected);
        assert_eq!(NullifierFlag::LEN, 9);
    }

    #[test]
    fn test_executed_flag_size() {
        let expected = 8 + 1;  // discriminator + bump
        assert_eq!(ExecutedFlag::LEN, expected);
        assert_eq!(ExecutedFlag::LEN, 9);
    }

    #[test]
    fn test_merkle_tree_capacity() {
        let capacity: u64 = 1u64 << TREE_DEPTH;
        assert_eq!(capacity, 67_108_864);
    }

    #[test]
    fn test_root_history_size() {
        assert!(ROOT_HISTORY >= 100);
        assert!(ROOT_HISTORY <= 1000);
    }
}
