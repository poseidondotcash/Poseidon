use anchor_lang::prelude::*;
use anchor_lang::system_program;
use crate::state::{GlobalState, NoteRecord, ExplosiveWithdrawal, NullifierFlag};
use crate::errors::ErrorCode;
use crate::constants::{
    MAX_INS, MAX_OUTS, RELAYER_FEE_BPS, BPS_DENOM, RELAYER_GAS_BUFFER_LAMPORTS,
    MAX_EXPLOSIVE_RECEIVERS, AUTHORIZED_RELAYER,
};
use crate::utils::{u64_to_be_32, pubkey_to_u64_limbs_le};
use crate::verification;
use crate::NR_PUBINPUTS_LOCAL;
use std::str::FromStr;

fn generate_random_splits(
    total_amount: u64,
    num_splits: usize,
    seed: u64,
) -> Result<[u64; MAX_EXPLOSIVE_RECEIVERS]> {
    require!(num_splits > 0 && num_splits <= MAX_EXPLOSIVE_RECEIVERS, ErrorCode::InvalidExplosiveSplit);
    require!(total_amount > 0, ErrorCode::InvalidExplosiveSplit);
    
    let mut splits = [0u64; MAX_EXPLOSIVE_RECEIVERS];
    let mut remaining = total_amount;
    
    let mut current_seed = seed;
    
    for i in 0..(num_splits - 1) {
        current_seed = current_seed.wrapping_mul(1103515245).wrapping_add(12345);
        
        let min_pct = 50;
        let max_pct = 200;
        let pct_range = max_pct - min_pct;
        let pct = min_pct + ((current_seed % pct_range as u64) as u64);
        
        let split_amount = remaining
            .checked_mul(pct)
            .ok_or(ErrorCode::Overflow)?
            / 1000;
        
        let split_amount = std::cmp::min(split_amount, remaining / 2);
        
        splits[i] = split_amount;
        remaining = remaining.checked_sub(split_amount).ok_or(ErrorCode::Overflow)?;
    }
    
    splits[num_splits - 1] = remaining;
    
    Ok(splits)
}

pub fn prepare_explosive_withdraw<'info>((
    ctx: Context<'_, '_, '_, 'info, PrepareExplosiveWithdraw<'info>>,
    _memo: Vec<u8>,
    parsed: crate::ParsedWithdrawMemo,
    intermediate_wallets: [Pubkey; MAX_EXPLOSIVE_RECEIVERS],
    nonce: u64,
) -> Result<()> {
    require!(parsed.nonce == nonce, ErrorCode::MemoParseError);
    
    const ZERO32: [u8; 32] = [0u8; 32];
    let rent = Rent::get()?;
    
    let num_nullifiers = parsed.input_nullifiers.iter()
        .take(parsed.n_inputs as usize)
        .filter(|nf| **nf != ZERO32)
        .count();
    
    let num_outputs = parsed.output_commitments.iter()
        .filter(|c| **c != ZERO32)
        .count();
    
    let nullifier_rent = rent.minimum_balance(NullifierFlag::LEN);
    let note_rent = rent.minimum_balance(NoteRecord::len_for(0));
    
    let total_rent_needed = nullifier_rent
        .checked_mul(num_nullifiers as u64)
        .and_then(|n| n.checked_add(note_rent.checked_mul(num_outputs as u64)?))
        .and_then(|n| n.checked_add(RELAYER_GAS_BUFFER_LAMPORTS))
        .ok_or(ErrorCode::Overflow)?;
    
    let escrow_balance = ctx.accounts.escrow.lamports();
    
    if escrow_balance < total_rent_needed {
        let need = total_rent_needed
            .checked_sub(escrow_balance)
            .ok_or(ErrorCode::Overflow)?;
        
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.signer.to_account_info(),
                    to: ctx.accounts.escrow.to_account_info(),
                },
            ),
            need,
        )?;
        
        msg!("💰 Topped up escrow by {} lamports ({} nullifiers, {} notes, current: {}, target: {})", 
             need, num_nullifiers, num_outputs, escrow_balance, total_rent_needed);
    }
    
    let authorized_relayer = Pubkey::from_str(AUTHORIZED_RELAYER)
        .map_err(|_| ErrorCode::Unauthorized)?;
    require_keys_eq!(
        ctx.accounts.relayer.key(),
        authorized_relayer,
        ErrorCode::Unauthorized
    );

    let recipient_pk = ctx.accounts.final_recipient.key();

    let limbs = pubkey_to_u64_limbs_le(&recipient_pk);
    let mut pubs_be: [[u8; 32]; NR_PUBINPUTS_LOCAL] = [[0u8; 32]; NR_PUBINPUTS_LOCAL];

    for i in 0..MAX_INS {
        pubs_be[i] = parsed.input_nullifiers[i];
    }

    let base_dest = MAX_INS;
    pubs_be[base_dest + 0] = u64_to_be_32(limbs[0]);
    pubs_be[base_dest + 1] = u64_to_be_32(limbs[1]);
    pubs_be[base_dest + 2] = u64_to_be_32(limbs[2]);
    pubs_be[base_dest + 3] = u64_to_be_32(limbs[3]);

    let base_out = MAX_INS + 4;
    for j in 0..MAX_OUTS {
        pubs_be[base_out + j] = parsed.output_commitments[j];
    }

    pubs_be[base_out + MAX_OUTS + 0] = u64_to_be_32(parsed.public_amount);
    pubs_be[base_out + MAX_OUTS + 1] = u64_to_be_32(parsed.ext_amount_in);

    verification::verify_groth16::<NR_PUBINPUTS_LOCAL>(
        &parsed.proof_a,
        &parsed.proof_b,
        &parsed.proof_c,
        &pubs_be,
    )?;

    let ext_in = parsed.ext_amount_in;
    if ext_in > 0 {
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.signer.to_account_info(),
                    to:   ctx.accounts.pool.to_account_info(),
                },
            ),
            ext_in,
        )?;

        ctx.accounts.state.total_deposited = ctx
            .accounts
            .state
            .total_deposited
            .checked_add(ext_in)
            .ok_or(ErrorCode::Overflow)?;
    }

    let perc_fee = parsed
        .public_amount
        .checked_mul(RELAYER_FEE_BPS)
        .ok_or(ErrorCode::Overflow)? / BPS_DENOM;

    let to_relayer = perc_fee
        .checked_add(RELAYER_GAS_BUFFER_LAMPORTS)
        .ok_or(ErrorCode::Overflow)?;

    require!(parsed.public_amount > to_relayer, ErrorCode::InsufficientWithdrawalAmount);
    let net_withdrawal = parsed.public_amount - to_relayer;

    let expected_pool_balance = ctx.accounts.pool.lamports()
        .checked_add(ext_in)
        .ok_or(ErrorCode::Overflow)?;
    
    require!(
        expected_pool_balance >= parsed.public_amount,
        ErrorCode::InsufficientPoolFunds
    );

    let split_amounts = generate_random_splits(
        net_withdrawal,
        MAX_EXPLOSIVE_RECEIVERS,
        parsed.nonce,
    )?;

    let sum: u64 = split_amounts.iter().take(MAX_EXPLOSIVE_RECEIVERS).sum();
    require!(sum == net_withdrawal, ErrorCode::InvalidExplosiveSplit);

    let mut remaining_idx = 0;

    for (i, nf) in parsed.input_nullifiers.iter().enumerate() {
        if (i as u32) >= parsed.n_inputs {
            break;
        }
        if *nf == ZERO32 {
            continue;
        }

        let (null_pda, null_bump) =
            Pubkey::find_program_address(&[b"null", nf], &crate::ID);

        let null_ai_ref = ctx
            .remaining_accounts
            .get(remaining_idx)
            .ok_or(error!(ErrorCode::MissingNullifierPda))?;
        
        require_keys_eq!(null_ai_ref.key(), null_pda, ErrorCode::MissingNullifierPda);
        remaining_idx += 1;

        require!(
            null_ai_ref.data_is_empty(),
            ErrorCode::NullifierAlreadyUsed
        );

        let null_rent = Rent::get()?.minimum_balance(NullifierFlag::LEN);
        system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::CreateAccount {
                    from: ctx.accounts.escrow.to_account_info(),
                    to:   null_ai_ref.to_account_info(),
                },
                &[
                    &[b"escrow", &[ctx.accounts.state.escrow_bump]],
                    &[b"null", nf.as_ref(), &[null_bump]],
                ],
            ),
            null_rent,
            NullifierFlag::LEN as u64,
            &crate::ID,
        )?;

        let mut nd = null_ai_ref.try_borrow_mut_data()?;
        nd[0..8].copy_from_slice(&NullifierFlag::DISCRIMINATOR);
        nd[8] = null_bump;
    }

    for (j, commitment) in parsed.output_commitments.iter().enumerate() {
        if *commitment == ZERO32 {
            continue;
        }

        let next_idx = ctx.accounts.state.next_index;
        let tree_idx = next_idx + (j as u32);
        
        let idx_be = tree_idx.to_be_bytes();
        let (note_pda, note_bump) =
            Pubkey::find_program_address(&[b"note", &idx_be], &crate::ID);

        let note_ai_ref = ctx
            .remaining_accounts
            .get(remaining_idx)
            .ok_or(error!(ErrorCode::MissingOutputNotePda))?;

        require_keys_eq!(note_ai_ref.key(), note_pda, ErrorCode::MissingOutputNotePda);
        remaining_idx += 1;

        require!(
            note_ai_ref.data_is_empty(),
            ErrorCode::NullifierAlreadyUsed
        );

        let cipher_len = 0;
        let note_size = NoteRecord::len_for(cipher_len);
        let note_rent = Rent::get()?.minimum_balance(note_size);

        system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::CreateAccount {
                    from: ctx.accounts.escrow.to_account_info(),
                    to:   note_ai_ref.to_account_info(),
                },
                &[
                    &[b"escrow", &[ctx.accounts.state.escrow_bump]],
                    &[b"note", &idx_be, &[note_bump]],
                ],
            ),
            note_rent,
            note_size as u64,
            &crate::ID,
        )?;

        let mut note_data = note_ai_ref.try_borrow_mut_data()?;
        note_data[0..8].copy_from_slice(&NoteRecord::DISCRIMINATOR);
        note_data[8] = note_bump;
        note_data[9..13].copy_from_slice(&tree_idx.to_le_bytes());
        note_data[13..45].copy_from_slice(commitment);
        note_data[45..77].copy_from_slice(&ctx.accounts.signer.key().to_bytes());
        note_data[77..85].copy_from_slice(&0u64.to_le_bytes());
        note_data[85..89].copy_from_slice(&0u32.to_le_bytes());
    }

    ctx.accounts.state.next_index = ctx.accounts.state.next_index
        .checked_add(MAX_OUTS as u32)
        .ok_or(ErrorCode::Overflow)?;

    let explosive = &mut ctx.accounts.explosive_withdrawal;
    explosive.bump = ctx.bumps.explosive_withdrawal;
    explosive.executed = false;
    explosive.nonce = parsed.nonce;
    explosive.final_recipient = recipient_pk;
    explosive.relayer = ctx.accounts.relayer.key();
    explosive.total_amount = parsed.public_amount;
    explosive.relayer_fee = to_relayer;
    explosive.num_receivers = MAX_EXPLOSIVE_RECEIVERS as u8;
    explosive.transfers_completed = 0; // No transfers done yet
    explosive.intermediate_wallets = intermediate_wallets;
    explosive.split_amounts = split_amounts;
    explosive.created_slot = Clock::get()?.slot;

    msg!("✅ Explosive withdrawal prepared:");
    msg!("  Nonce: {}", parsed.nonce);
    msg!("  Total: {} lamports", parsed.public_amount);
    msg!("  Net withdrawal: {} lamports split across {} wallets", net_withdrawal, MAX_EXPLOSIVE_RECEIVERS);
    msg!("  Relayer fee: {} lamports", to_relayer);

    Ok(())
}

pub fn execute_explosive_single<'info>(
    ctx: Context<'_, '_, 'info, 'info, ExecuteExplosiveSingle<'info>>,
    wallet_index: u8,
) -> Result<()> {
    let explosive = &mut ctx.accounts.explosive_withdrawal;
    
    require!(wallet_index < explosive.num_receivers, ErrorCode::InvalidExplosiveSplit);
    require!(!explosive.executed, ErrorCode::AlreadyExecuted);
    require_keys_eq!(
        ctx.accounts.relayer.key(),
        explosive.relayer,
        ErrorCode::Unauthorized
    );
    
    let mask = 1u16 << wallet_index;
    require!(explosive.transfers_completed & mask == 0, ErrorCode::AlreadyExecuted);
    
    let pool_bump = ctx.accounts.state.pool_bump;
    let amount = explosive.split_amounts[wallet_index as usize];
    
    if amount > 0 {
        let wallet = &ctx.remaining_accounts[0];
        require_keys_eq!(
            wallet.key(),
            explosive.intermediate_wallets[wallet_index as usize],
            ErrorCode::InvalidIntermediateWallet
        );
        
        system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.pool.to_account_info(),
                    to: wallet.to_account_info(),
                },
                &[&[b"pool", &[pool_bump]]],
            ),
            amount,
        )?;
        
        msg!("💸 Transferred {} lamports to wallet {}", amount, wallet_index);
    }
    
    explosive.transfers_completed |= mask;
    
    let all_complete = (1u16 << explosive.num_receivers) - 1;
    if explosive.transfers_completed == all_complete {
        system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.pool.to_account_info(),
                    to: ctx.accounts.relayer.to_account_info(),
                },
                &[&[b"pool", &[pool_bump]]],
            ),
            explosive.relayer_fee,
        )?;
        
        ctx.accounts.state.total_withdrawn = ctx.accounts.state.total_withdrawn
            .checked_add(explosive.total_amount)
            .ok_or(ErrorCode::Overflow)?;
        
        explosive.executed = true;
        msg!("✅ All {} transfers complete! Relayer fee: {} lamports", explosive.num_receivers, explosive.relayer_fee);
    }
    
    Ok(())
}

pub fn execute_explosive_withdraw<'info>(
    ctx: Context<'_, '_, 'info, 'info, ExecuteExplosiveWithdraw<'info>>,
) -> Result<()> {
    let explosive = &ctx.accounts.explosive_withdrawal;
    
    require!(!explosive.executed, ErrorCode::AlreadyExecuted);
    require_keys_eq!(
        ctx.accounts.relayer.key(),
        explosive.relayer,
        ErrorCode::Unauthorized
    );

    let pool_bump = ctx.accounts.state.pool_bump;
    let num_receivers = explosive.num_receivers as usize;
    let split_amounts = explosive.split_amounts;
    let intermediate_wallets = explosive.intermediate_wallets;
    let relayer_fee = explosive.relayer_fee;
    let total_amount = explosive.total_amount;

    require!(
        ctx.remaining_accounts.len() >= num_receivers,
        ErrorCode::MissingIntermediateWallet
    );

    for i in 0..num_receivers {
        let amount = split_amounts[i];
        if amount == 0 {
            continue;
        }

        let wallet_ai = &ctx.remaining_accounts[i];
        
        require_keys_eq!(
            wallet_ai.key(),
            intermediate_wallets[i],
            ErrorCode::InvalidIntermediateWallet
        );

        system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.pool.to_account_info(),
                    to: wallet_ai.to_account_info(),
                },
                &[&[b"pool", &[pool_bump]]],
            ),
            amount,
        )?;
    }

    system_program::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.pool.to_account_info(),
                to: ctx.accounts.relayer.to_account_info(),
            },
            &[&[b"pool", &[pool_bump]]],
        ),
        relayer_fee,
    )?;

    ctx.accounts.state.total_withdrawn = ctx.accounts.state.total_withdrawn
        .checked_add(total_amount)
        .ok_or(ErrorCode::Overflow)?;
    
    let explosive = &mut ctx.accounts.explosive_withdrawal;

    explosive.executed = true;

    msg!("✅ Explosive withdrawal executed:");
    msg!("  {} lamports distributed across {} intermediate wallets", 
         explosive.total_amount - explosive.relayer_fee, 
         explosive.num_receivers);
    msg!("  Relayer received {} lamports", explosive.relayer_fee);

    Ok(())
}

#[derive(Accounts)]
#[instruction(_memo: Vec<u8>, intermediate_wallets: [Pubkey; 10], nonce: u64)]
pub struct PrepareExplosiveWithdraw<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, GlobalState>,

    /// CHECK: Pool PDA for transfers
    #[account(
        mut,
        seeds = [b"pool"],
        bump = state.pool_bump,
    )]
    pub pool: AccountInfo<'info>,

    /// CHECK: Escrow PDA for creating accounts
    #[account(
        mut,
        seeds = [b"escrow"],
        bump = state.escrow_bump,
    )]
    pub escrow: AccountInfo<'info>,

    /// Final recipient (will receive bundled funds later)
    /// CHECK: Validated via ZK proof
    pub final_recipient: AccountInfo<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    #[account(
        init,
        payer = relayer,
        space = ExplosiveWithdrawal::LEN,
        seeds = [b"explo", nonce.to_be_bytes().as_ref()],
        bump,
    )]
    pub explosive_withdrawal: Account<'info, ExplosiveWithdrawal>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExecuteExplosiveWithdraw<'info> {
    #[account(
        mut,
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, GlobalState>,

    /// CHECK: Pool PDA
    #[account(
        mut,
        seeds = [b"pool"],
        bump = state.pool_bump,
    )]
    pub pool: AccountInfo<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    #[account(
        mut,
        seeds = [b"explo", explosive_withdrawal.nonce.to_be_bytes().as_ref()],
        bump = explosive_withdrawal.bump,
    )]
    pub explosive_withdrawal: Account<'info, ExplosiveWithdrawal>,

    pub system_program: Program<'info, System>,
}

/// Accounts for executing a single transfer from an explosive withdrawal
#[derive(Accounts)]
pub struct ExecuteExplosiveSingle<'info> {
    #[account(
        mut,
        seeds = [b"state"],
        bump = state.bump,
    )]
    pub state: Account<'info, GlobalState>,

    /// CHECK: Pool PDA
    #[account(
        mut,
        seeds = [b"pool"],
        bump = state.pool_bump,
    )]
    pub pool: AccountInfo<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    #[account(
        mut,
        seeds = [b"explo", explosive_withdrawal.nonce.to_be_bytes().as_ref()],
        bump = explosive_withdrawal.bump,
    )]
    pub explosive_withdrawal: Account<'info, ExplosiveWithdrawal>,

    pub system_program: Program<'info, System>,
}
