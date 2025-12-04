use anchor_lang::prelude::*;
use crate::constants::{TREE_DEPTH, ROOT_HISTORY};

#[account]
pub struct GlobalState {
    pub admin: Pubkey,
    pub bump: u8,
    pub escrow_bump: u8,
    pub pool_bump: u8,
    pub next_index: u32,
    pub current_root: [u8; 32],
    pub root_history_idx: u8,
    pub zeroes: Vec<u8>,
    pub filled_subtrees: Vec<u8>,
    pub root_history: Vec<u8>,
    pub total_deposited: u64,
    pub total_withdrawn: u64,
}

impl GlobalState {
    pub const LEN: usize =
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

/// Nullifier flag to prevent double-spending
///
/// Each spent note has a corresponding nullifier PDA that gets created
/// during withdrawal, making it impossible to spend the same note twice.
#[account]
pub struct NullifierFlag {
    pub bump: u8,
}

impl NullifierFlag {
    pub const LEN: usize = 8 + 1; // discriminator + bump
}

#[account]
pub struct ExecutedFlag {
    pub bump: u8,
}

impl ExecutedFlag {
    pub const LEN: usize = 8 + 1; // discriminator + bump
}

/// Note record containing commitment and encrypted note data
///
/// This is manually serialized (not using #[account] macro) to support
/// variable-length ciphertext. Each note includes emergency recovery data.
pub struct NoteRecord {
    pub bump: u8,
    pub index: u32,
    pub commitment: [u8; 32],
    
    /// Original depositor (for emergency recovery only)
    pub depositor: Pubkey,
    
    /// Amount deposited (for emergency recovery only)
    pub amount: u64,
    
    /// Encrypted note data (variable length)
    /// Contains: balance, note_nonce, owner_pubkey
    pub ciphertext: Vec<u8>,
}

impl NoteRecord {
    /// Anchor discriminator for NoteRecord accounts
    pub const DISCRIMINATOR: [u8; 8] = [137, 203, 175, 143, 240, 77, 171, 218];

    /// Calculate account size for a given ciphertext length
    pub fn len_for(cipher_len: usize) -> usize {
        8       // discriminator
        + 1     // bump
        + 4     // index
        + 32    // commitment
        + 32    // depositor
        + 8     // amount
        + 4     // ciphertext length prefix
        + cipher_len
    }

    /// Serialize to bytes for account data
    pub fn try_serialize<'a>(&self, dst: &'a mut &'a mut [u8]) -> std::io::Result<()> {
        // Write discriminator
        dst[..8].copy_from_slice(&Self::DISCRIMINATOR);
        *dst = &mut std::mem::take(dst)[8..];

        // Write fields
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

/// Prepared withdrawal transaction
///
/// Created during the "prepare" phase of a withdrawal, this locks in
/// all withdrawal parameters. The "execute" phase transfers funds
/// according to these parameters, preventing parameter tampering.
#[account]
pub struct PreparedTx {
    pub bump: u8,
    pub executed: bool,

    /// Unique nonce (also a ZK public input)
    pub nonce: u64,
    
    /// Withdrawal recipient
    pub recipient: Pubkey,
    
    /// Relayer who will execute the withdrawal
    pub relayer: Pubkey,

    /// Amount to send to recipient (public_amount - fee)
    pub to_recipient: u64,
    
    /// Relayer fee
    pub to_relayer: u64,
}

impl PreparedTx {
    /// Account size in bytes
    pub const LEN: usize =
        8       // discriminator
        + 1     // bump
        + 1     // executed
        + 8     // nonce
        + 32    // recipient
        + 32    // relayer
        + 8     // to_recipient
        + 8;    // to_relayer
}

/// Explosive withdrawal state - splits withdrawal across multiple intermediate wallets
///
/// This provides additional privacy by splitting a single withdrawal into random amounts
/// across multiple intermediate wallets, then bundling them to the final recipient.
/// The relayer signs the initial split, then a bundler collects all splits.
#[account]
pub struct ExplosiveWithdrawal {
    pub bump: u8,
    pub executed: bool,
    
    /// Unique nonce for this explosive withdrawal
    pub nonce: u64,
    
    /// Final recipient (will receive bundled amount)
    pub final_recipient: Pubkey,
    
    /// Relayer executing the explosive withdrawal
    pub relayer: Pubkey,
    
    /// Total amount being withdrawn (before fees)
    pub total_amount: u64,
    
    /// Total relayer fee
    pub relayer_fee: u64,
    
    /// Number of intermediate receivers (typically MAX_EXPLOSIVE_RECEIVERS)
    pub num_receivers: u8,
    
    /// Bitmask tracking which transfers have been completed (bit i = wallet i)
    pub transfers_completed: u16,
    
    /// Intermediate wallet public keys (MAX_EXPLOSIVE_RECEIVERS)
    pub intermediate_wallets: [Pubkey; crate::constants::MAX_EXPLOSIVE_RECEIVERS],
    
    /// Random amounts sent to each intermediate wallet
    pub split_amounts: [u64; crate::constants::MAX_EXPLOSIVE_RECEIVERS],
    
    /// Slot when this was created (for expiry)
    pub created_slot: u64,
}

impl ExplosiveWithdrawal {
    /// Account size in bytes
    pub const LEN: usize =
        8       // discriminator
        + 1     // bump
        + 1     // executed
        + 8     // nonce
        + 32    // final_recipient
        + 32    // relayer
        + 8     // total_amount
        + 8     // relayer_fee
        + 1     // num_receivers
        + 2     // transfers_completed (u16 bitmask)
        + (32 * crate::constants::MAX_EXPLOSIVE_RECEIVERS)  // intermediate_wallets
        + (8 * crate::constants::MAX_EXPLOSIVE_RECEIVERS)   // split_amounts
        + 8;    // created_slot
}
