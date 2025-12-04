#![deny(unused_must_use)]
#![allow(ambiguous_glob_reexports)]
#![allow(hidden_glob_reexports)]
#![allow(unexpected_cfgs)]

mod utils;
mod instructions;
mod vk;

#[cfg(test)]
mod tests;

pub use utils::*;
pub use instructions::*;

use anchor_lang::prelude::*;

declare_id!("7oncpraGxTtXjkQsQytWQRYNCuRKXHkHzypMdpfjEwLN");
// Number of main public signals (taken from VK to avoid drift)
pub const NR_PUBINPUTS_LOCAL: usize = vk::VK_NR_PUBINPUTS;

#[program]
pub mod privacy_wallet {
    use super::*;

    pub fn init_state(ctx: Context<InitState>) -> Result<()> {
        instructions::init::init_state(ctx)
    }

    pub fn deposit_with_note<'info>(
        ctx: Context<'_, '_, '_, 'info, DepositWithNote<'info>>,
        amount: u64,
        commitment: [u8; 32],
        ciphertext: Vec<u8>,
    ) -> Result<()> {
        instructions::deposit::deposit_with_note(ctx, amount, commitment, ciphertext)
    }

    pub fn prepare_withdraw_via_memo<'info>(
        ctx: Context<'_, '_, '_, 'info, PrepareWithdraw<'info>>,
        memo: Vec<u8>,
    ) -> Result<()> {
        let parsed = parse_withdraw_memo(&memo)?;
        instructions::withdraw::prepare_withdraw_via_memo(ctx, memo, parsed)
    }

    pub fn execute_prepared_withdraw(ctx: Context<ExecutePrepared>) -> Result<()> {
        instructions::withdraw::execute_prepared_withdraw(ctx)
    }

    pub fn fetch_note(ctx: Context<FetchNote>, commitment: [u8; 32]) -> Result<()> {
        instructions::fetch::fetch_note(ctx, commitment)
    }

    pub fn emergency_withdraw(
        ctx: Context<EmergencyWithdraw>,
        commitment: [u8; 32],
    ) -> Result<()> {
        instructions::emergency::emergency_withdraw(ctx, commitment)
    }

    pub fn prepare_explosive_withdraw<'info>(
        ctx: Context<'_, '_, '_, 'info, PrepareExplosiveWithdraw<'info>>,
        memo: Vec<u8>,
        intermediate_wallets: [Pubkey; MAX_EXPLOSIVE_RECEIVERS],
        nonce: u64,
    ) -> Result<()> {
        let parsed = parse_withdraw_memo(&memo)?;
        instructions::explosive::prepare_explosive_withdraw(ctx, memo, parsed, intermediate_wallets, nonce)
    }

    pub fn execute_explosive_withdraw<'info>(
        ctx: Context<'_, '_, 'info, 'info, ExecuteExplosiveWithdraw<'info>>,
    ) -> Result<()> {
        instructions::explosive::execute_explosive_withdraw(ctx)
    }

    pub fn delete_orphaned_nullifier(
        ctx: Context<DeleteOrphanedNullifier>,
        commitment: [u8; 32],
        nullifier: [u8; 32],
    ) -> Result<()> {
        instructions::cleanup::delete_orphaned_nullifier(ctx, commitment, nullifier)
    }

    pub fn execute_explosive_single<'info>(
        ctx: Context<'_, '_, 'info, 'info, ExecuteExplosiveSingle<'info>>,
        wallet_index: u8,
    ) -> Result<()> {
        instructions::explosive::execute_explosive_single(ctx, wallet_index)
    }

    pub fn emergency_recover_with_salt(
        ctx: Context<EmergencyRecoverWithSalt>,
        commitment: [u8; 32],
        salt: u64,
    ) -> Result<()> {
        instructions::recover::emergency_recover_with_salt(ctx, commitment, salt)
    }

    pub fn emergency_recover_orphaned(
        ctx: Context<EmergencyRecoverOrphaned>,
        commitment: [u8; 32],
        amount: u64,
        salt: u64,
        depositor_override: Pubkey,
    ) -> Result<()> {
        instructions::recover::emergency_recover_orphaned(ctx, commitment, amount, salt, depositor_override)
    }
}

/* ============================== Memo Parsing ================================ */

pub struct ParsedWithdrawMemo {
    pub proof_a: [u8;64],
    pub proof_b: [u8;128],
    pub proof_c: [u8;64],

    pub public_amount: u64,
    pub ext_amount_in: u64,
    pub nonce: u64,

    pub n_inputs: u32,

    pub input_nullifiers: [[u8;32]; MAX_INS],
    pub output_commitments: [[u8;32]; MAX_OUTS],
}

fn parse_withdraw_memo(memo: &[u8]) -> Result<ParsedWithdrawMemo> {
    let mut off = 0usize;

    let proof_a       = read_arr::<64>(memo, &mut off)?;
    let proof_b       = read_arr::<128>(memo, &mut off)?;
    let proof_c       = read_arr::<64>(memo, &mut off)?;
    let public_amount = read_u64_le(memo, &mut off)?;
    let ext_amount_in = read_u64_le(memo, &mut off)?;
    let nonce         = read_u64_le(memo, &mut off)?;

    let n_inputs      = read_u32_le(memo, &mut off)?;
    require!((n_inputs as usize) <= MAX_INS, errors::ErrorCode::MemoParseError);

    let mut input_nullifiers = [[0u8; 32]; MAX_INS];
    for i in 0..MAX_INS {
        input_nullifiers[i] = read_arr::<32>(memo, &mut off)?;
    }

    // Read flag (1 byte)
    require!(off + 1 <= memo.len(), errors::ErrorCode::MemoParseError);
    let flag = memo[off];
    off += 1;

    let is_full_withdraw = flag == 1;

    let mut output_commitments = [[0u8; 32]; MAX_OUTS];
    if is_full_withdraw {
        // Reconstruct zeros (no further read)
        for i in 0..MAX_OUTS {
            output_commitments[i] = [0u8; 32];
        }
    } else {
        require!(off + 1 <= memo.len(), errors::ErrorCode::MemoParseError);
        let non_zero_count = memo[off] as usize;
        off += 1;

        require!(non_zero_count <= MAX_OUTS, errors::ErrorCode::MemoParseError);

        for i in 0..MAX_OUTS {
            output_commitments[i] = [0u8; 32];
        }

        let mut last_idx: i16 = -1;
        for _ in 0..non_zero_count {
            require!(off + 1 <= memo.len(), errors::ErrorCode::MemoParseError);
            let idx = memo[off] as usize;
            off += 1;

            require!((idx as i16) > last_idx, errors::ErrorCode::InvalidCompressedMemoIndex);
            require!(idx < MAX_OUTS, errors::ErrorCode::MemoParseError);
            
            output_commitments[idx] = read_arr::<32>(memo, &mut off)?;
            last_idx = idx as i16;
        }
    }

    require!(off == memo.len(), errors::ErrorCode::MemoParseError);

    Ok(ParsedWithdrawMemo {
        proof_a,
        proof_b,
        proof_c,
        public_amount,
        ext_amount_in,
        nonce,
        n_inputs,
        input_nullifiers,
        output_commitments,
    })
}
