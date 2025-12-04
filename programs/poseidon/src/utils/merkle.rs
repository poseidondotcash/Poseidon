use anchor_lang::prelude::*;
use light_hasher::{Hasher, Poseidon};
use crate::constants::{TREE_DEPTH, ROOT_HISTORY};
use crate::state::GlobalState;
use crate::errors::ErrorCode;

#[inline]
pub fn hash2(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    Poseidon::hashv(&[a.as_slice(), b.as_slice()])
        .expect("Poseidon hash should never fail with valid inputs")
}

pub fn insert_leaf(state: &mut GlobalState, leaf: [u8; 32]) -> Result<(u32, [u8; 32])> {
    let mut idx = state.next_index;
    
    require!(
        (idx as u64) < (1u64 << TREE_DEPTH),
        ErrorCode::TreeFull
    );

    let zeroes: &[[u8; 32]] = bytemuck::cast_slice(&state.zeroes);
    let filled: &mut [[u8; 32]] = bytemuck::cast_slice_mut(&mut state.filled_subtrees);
    let mut cur = leaf;
    for lvl in 0..TREE_DEPTH {
        if (idx & 1) == 0 {
            // Left child: store current hash, hash with zero
            filled[lvl] = cur;
            cur = hash2(&cur, &zeroes[lvl]);
        } else {
            // Right child: hash stored left sibling with current
            let left = filled[lvl];
            cur = hash2(&left, &cur);
        }
        idx >>= 1;
    }

    let new_root = cur;
    
    // Update current root
    state.current_root = new_root;

    // Add to circular root history buffer
    let pos = (state.root_history_idx as usize + 1) % ROOT_HISTORY;
    let root_history: &mut [[u8; 32]] = bytemuck::cast_slice_mut(&mut state.root_history);
    root_history[pos] = new_root;
    state.root_history_idx = pos as u8;

    // Increment next_index with overflow check
    let inserted_at = state.next_index;
    state.next_index = state
        .next_index
        .checked_add(1)
        .ok_or(ErrorCode::Overflow)?;
    
    Ok((inserted_at, new_root))
}

pub fn validate_root_in_history(state: &GlobalState, root: &[u8; 32]) -> Result<()> {
    // Check current root first (most common case)
    if &state.current_root == root {
        return Ok(());
    }

    // Check historical roots
    let root_history: &[[u8; 32]] = bytemuck::cast_slice(&state.root_history);
    for historical_root in root_history.iter() {
        if historical_root == root {
            return Ok(());
        }
    }

    Err(ErrorCode::UnknownRoot.into())
}

pub fn compute_zero_values() -> Vec<u8> {
    let mut zeroes = vec![[0u8; 32]; TREE_DEPTH];
    
    // Level 0 is all zeros (empty leaf)
    // Each subsequent level is hash(prev_zero, prev_zero)
    for i in 1..TREE_DEPTH {
        zeroes[i] = hash2(&zeroes[i - 1], &zeroes[i - 1]);
    }
    
    // Flatten to bytes
    zeroes.into_iter().flatten().collect()
}
