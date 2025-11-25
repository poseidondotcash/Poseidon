//! State migration utilities

use anchor_lang::prelude::*;
use light_hasher::{Hasher, Poseidon};
use crate::state::GlobalState;
use crate::errors::ErrorCode;
use crate::constants::TREE_DEPTH;

/// Migrate existing state to use Poseidon zero bytes
pub fn migrate_to_poseidon(ctx: Context<MigrateState>) -> Result<()> {
    let s = &mut ctx.accounts.state;
    require!(s.admin == ctx.accounts.admin.key(), ErrorCode::Unauthorized);

    let poseidon_zeros = Poseidon::zero_bytes();
    
    // Update zeroes array
    {
        let zeroes_arr: &mut [[u8; 32]] = bytemuck::cast_slice_mut(&mut s.zeroes);
        for lvl in 0..TREE_DEPTH {
            zeroes_arr[lvl] = poseidon_zeros[lvl];
        }
    }

    // Re-initialize filled_subtrees and root if tree is empty
    if s.next_index == 0 {
        {
            let filled_arr: &mut [[u8; 32]] = bytemuck::cast_slice_mut(&mut s.filled_subtrees);
            for lvl in 0..TREE_DEPTH {
                filled_arr[lvl] = poseidon_zeros[lvl];
            }
        }
        let new_root = poseidon_zeros[TREE_DEPTH];
        s.current_root = new_root;
        {
            let root_history_arr: &mut [[u8; 32]] = bytemuck::cast_slice_mut(&mut s.root_history);
            root_history_arr[0] = new_root;
        }
    }

    Ok(())
}

#[derive(Accounts)]
pub struct MigrateState<'info> {
    #[account(mut, seeds = [b"state"], bump = state.bump)]
    pub state: Account<'info, GlobalState>,
    
    #[account(mut)]
    pub admin: Signer<'info>,
}
