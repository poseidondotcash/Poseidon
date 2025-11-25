//! Initialize program state

use anchor_lang::prelude::*;
use anchor_lang::system_program;
use light_hasher::{Hasher, Poseidon};
use crate::state::GlobalState;
use crate::constants::{TREE_DEPTH, ROOT_HISTORY};

/// Initialize the privacy wallet state
pub fn init_state(ctx: Context<InitState>) -> Result<()> {
    let s = &mut ctx.accounts.state;
    s.admin       = ctx.accounts.payer.key();
    s.bump        = ctx.bumps.state;
    s.escrow_bump = ctx.bumps.escrow;
    s.pool_bump   = ctx.bumps.pool;

    let mut zeroes = vec![0u8; TREE_DEPTH * 32];
    let mut filled_subtrees = vec![0u8; TREE_DEPTH * 32];
    let mut root_history = vec![0u8; ROOT_HISTORY * 32];

    let zeroes_arr: &mut [[u8; 32]] = bytemuck::cast_slice_mut(&mut zeroes);
    let filled_arr: &mut [[u8; 32]] = bytemuck::cast_slice_mut(&mut filled_subtrees);

    // Initialize using Poseidon zero bytes from light-hasher
    let poseidon_zeros = Poseidon::zero_bytes();
    for lvl in 0..TREE_DEPTH {
        zeroes_arr[lvl] = poseidon_zeros[lvl];
        filled_arr[lvl] = poseidon_zeros[lvl];
    }
    s.current_root = poseidon_zeros[TREE_DEPTH];
    root_history[..32].copy_from_slice(&s.current_root);
    s.root_history_idx = 0;
    s.next_index = 0;

    s.zeroes = zeroes;
    s.filled_subtrees = filled_subtrees;
    s.root_history = root_history;

    // accounting
    s.total_deposited = 0;
    s.total_withdrawn = 0;

    Ok(())
}

#[derive(Accounts)]
pub struct InitState<'info> {
    #[account(init, payer = payer, space = GlobalState::LEN, seeds = [b"state"], bump)]
    pub state: Account<'info, GlobalState>,

    /// CHECK: PDA used as rent payer, owned by system
    #[account(init, payer = payer, seeds = [b"escrow"], bump, space = 0, owner = system_program::ID)]
    pub escrow: UncheckedAccount<'info>,

    /// CHECK: Shared lamport pool, owned by system
    #[account(init, payer = payer, seeds = [b"pool"], bump, space = 0, owner = system_program::ID)]
    pub pool: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}
