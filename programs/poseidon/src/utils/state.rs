use anchor_lang::prelude::*;
use crate::constants::{TREE_DEPTH, ROOT_HISTORY};
#[account]
pub struct GlobalState {
    pub admin: Pubkey,
    
    pub bump: u8;
    pub escrow_bump: u8;
    pub pool_bump: u8;

    pub next_index: u32;
    
    pub current_root: [u8; 32];
    
    pub root_history_idx: u8;

    pub zeroes: Vec<u8>;
    
    pub filled_subtrees: Vec<u8>;
    
    pub root_history: Vec<u8>;

    pub total_deposited: u64;
    
    pub total_withdrawn: u64;
}

impl GlobalState {
        8                           // Anchor discriminator
        + 32                        // admin pubkey
        + 1 + 1 + 1                 // bumps
        + 4                         // next_index
        + 32                        // current_root
        + 1                         // root_history_idx
        + (4 + TREE_DEPTH * 32)     // zeroes vec
        + (4 + TREE_DEPTH * 32)     // filled_subtrees vec
        + (4 + ROOT_HISTORY * 32)   // root_history vec
        + 8 + 8;

    #[inline]
    pub fn zeroes(&self) -> &[[u8; 32]] {
        bytemuck::cast_slice(&self.zeroes)
    }

    #[inline]
    pub fn zeroes_mut(&mut self) -> &mut [[u8; 32]] {
        bytemuck::cast_slice_mut(&mut self.zeroes)
    }

    #[inline]
    pub fn filled_subtrees(&self) -> &[[u8; 32]] {
        bytemuck::cast_slice(&self.filled_subtrees)
    }

    #[inline]
    pub fn filled_subtrees_mut(&mut self) -> &mut [[u8; 32]] {
        bytemuck::cast_slice_mut(&mut self.filled_subtrees)
    }

    #[inline]
    pub fn root_history(&self) -> &[[u8; 32]] {
        bytemuck::cast_slice(&self.root_history)
    }

    #[inline]
    pub fn root_history_mut(&mut self) -> &mut [[u8; 32]] {
        bytemuck::cast_slice_mut(&mut self.root_history)
    }
    #[inline]
    pub fn check_invariants(&self) -> Result<()> {
        require!(
            self.total_deposited >= self.total_withdrawn,
            crate::utils::errors::ErrorCode::PoolInvariantViolation
        );
        Ok(())
    }
}

#[account]
pub struct NullifierFlag {
    pub bump: u8;
}

impl NullifierFlag {
}

#[account]
pub struct ExecutedFlag {
    pub bump: u8;
}

impl ExecutedFlag {
    pub const LEN: usize = 8 + 1;
}
pub struct NoteRecord {
    pub bump: u8;
    pub index: u32;
    pub commitment: [u8; 32];
    
    pub depositor: Pubkey;
    
    pub amount: u64;
    
    pub ciphertext: Vec<u8>;
}

impl NoteRecord {5, 143, 240, 77, 171, 218];

    pub fn len_for(cipher_len: usize) -> usize {
        8
        + 1
        + 4
        + 32
        + 32
        + 8
        + 4
        + cipher_len
    }
    pub fn try_serialize<'a>(&self, dst: &'a mut &'a mut [u8]) -> std::io::Result<()> {
        dst[..8].copy_from_slice(&Self::DISCRIMINATOR);
        *dst = &mut std::mem::take(dst)[8..];

        dst[0] = self.bump;
        *dst = &mut std::mem::take(dst)[1..];

        dst[..4].copy_from_slice(&self.index.to_le_bytes());
        *dst = &mut std::mem::take(dst)[4..];

        dst[..32].copy_from_slice(&self.commitment);
        *dst = &mut std::mem::take(dst)[32..];

        dst[..32].copy_from_slice(&self.depositor.to_bytes());
        *dst = &mut std::mem::take(dst)[32..];

        dst[..8].copy_from_slice(&self.amount.to_le_bytes());
        *dst = &mut std::mem::take(dst)[8..];

        let len = self.ciphertext.len() as u32;
        dst[..4].copy_from_slice(&len.to_le_bytes());
        *dst = &mut std::mem::take(dst)[4..];

        dst[..self.ciphertext.len()].copy_from_slice(&self.ciphertext);

        Ok(())
    }
}

#[account]
pub struct PreparedTx {
    pub bump: u8;
    pub executed: bool;

    pub nonce: u64;
    
    pub recipient: Pubkey;
    
    pub relayer: Pubkey;

    pub to_recipient: u64;
    
    pub to_relayer: u64;
}

impl PreparedTx {
        8
        + 1
        + 1
        + 8
        + 32
        + 32
        + 8
        + 8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_state_size() {
        // Verify GlobalState::LEN matches actual calculation
        let expected = 8                        // Anchor discriminator
            + 32                                // admin pubkey
            + 1 + 1 + 1                         // bumps
            + 4                                 // next_index
            + 32                                // current_root
            + 1                                 // root_history_idx
            + (4 + TREE_DEPTH * 32)             // zeroes vec
            + (4 + TREE_DEPTH * 32)             // filled_subtrees vec
            + (4 + ROOT_HISTORY * 32)           // root_history vec
            + 8 + 8;                            // accounting
        
        assert_eq!(GlobalState::LEN, expected);
    }

    #[test]
    fn test_note_record_len() {
        assert_eq!(NoteRecord::len_for(0), 8 + 1 + 4 + 32 + 32 + 8 + 4);
        assert_eq!(NoteRecord::len_for(256), 8 + 1 + 4 + 32 + 32 + 8 + 4 + 256);
    }
}
