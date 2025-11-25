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
            filled[lvl] = cur;
            cur = hash2(&cur, &zeroes[lvl]);
        } else {
            let left = filled[lvl];
            cur = hash2(&left, &cur);
        }
        idx >>= 1;
    }

    let new_root = cur;
    
    state.current_root = new_root;

    let pos = (state.root_history_idx as usize + 1) % ROOT_HISTORY;
    let root_history: &mut [[u8; 32]] = bytemuck::cast_slice_mut(&mut state.root_history);
    root_history[pos] = new_root;
    state.root_history_idx = pos as u8;

    let inserted_at = state.next_index;
    state.next_index = state
        .next_index
        .checked_add(1)
        .ok_or(ErrorCode::Overflow)?;
    
    Ok((inserted_at, new_root))
}

pub fn validate_root_in_history(state: &GlobalState, root: &[u8; 32]) -> Result<()> {
    if &state.current_root == root {
        return Ok(());
    }

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
    
    for i in 1..TREE_DEPTH {
        zeroes[i] = hash2(&zeroes[i - 1], &zeroes[i - 1]);
    }
    
    zeroes.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash2_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let hash1 = hash2(&a, &b);
        let hash2_result = hash2(&a, &b);
        assert_eq!(hash1, hash2_result, "Hash should be deterministic");
    }

    #[test]
    fn test_hash2_different_order() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let hash_ab = hash2(&a, &b);
        let hash_ba = hash2(&b, &a);
        assert_ne!(hash_ab, hash_ba, "Hash should depend on order");
    }

    #[test]
    fn test_zero_values_length() {
        let zeroes = compute_zero_values();
        assert_eq!(zeroes.len(), TREE_DEPTH * 32);
    }

    #[test]
    fn test_zero_values_progressive() {
        let zeroes_flat = compute_zero_values();
        let zeroes: Vec<[u8; 32]> = zeroes_flat
            .chunks(32)
            .map(|chunk| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(chunk);
                arr
            })
            .collect();

        // First zero should be all zeros
        assert_eq!(zeroes[0], [0u8; 32]);

        // Each subsequent should be hash of previous with itself
        for i in 1..TREE_DEPTH {
            let expected = hash2(&zeroes[i - 1], &zeroes[i - 1]);
            assert_eq!(zeroes[i], expected);
        }
    }
}
