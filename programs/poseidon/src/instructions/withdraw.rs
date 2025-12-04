use anchor_lang::prelude::*;
use anchor_lang::system_program;
use crate::state::{GlobalState, NoteRecord, PreparedTx, NullifierFlag};
use crate::errors::ErrorCode;
use crate::constants::{MAX_INS, MAX_OUTS, RELAYER_FEE_BPS, BPS_DENOM, RELAYER_GAS_BUFFER_LAMPORTS, RENT_WIGGLE, AUTHORIZED_RELAYER};
use crate::utils::{u64_to_be_32, pubkey_to_u64_limbs_le};
use crate::verification;
use crate::NR_PUBINPUTS_LOCAL;
use crate::ParsedWithdrawMemo;
use std::str::FromStr;

pub fn prepare_withdraw_via_memo<'info>(
    ctx: Context<'_, '_, '_, 'info, PrepareWithdraw<'info>>,
    _memo: Vec<u8>,
    parsed: ParsedWithdrawMemo,
) -> Result<()> {
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
    let note_rent = rent.minimum_balance(NoteRecord::len_for(0)); // 0 cipher for change notes
    let prep_rent = rent.minimum_balance(PreparedTx::LEN);
    
    let total_rent_needed = nullifier_rent
        .checked_mul(num_nullifiers as u64)
        .and_then(|n| n.checked_add(note_rent.checked_mul(num_outputs as u64)?))
        .and_then(|n| n.checked_add(prep_rent))
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

    let recipient_pk = ctx.accounts.recipient.key();

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
    let to_recipient = parsed.public_amount - to_relayer;

    let total_payout = to_recipient
        .checked_add(to_relayer)
        .ok_or(ErrorCode::Overflow)?;

    let expected_pool_balance = ctx.accounts.pool.lamports()
        .checked_add(ext_in)
        .ok_or(ErrorCode::Overflow)?;
    
    require!(
        expected_pool_balance >= total_payout,
        ErrorCode::InsufficientPoolFunds
    );

    let mut remaining_idx = 0;

    for (i, nf) in parsed.input_nullifiers.iter().enumerate() {
        if (i as u32) >= parsed.n_inputs {
            break;
        }
        if *nf == ZERO32 {
            continue;
        }

        let (null_pda, _null_bump) =
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

        ctx.accounts.state.next_index = tree_idx + 1;
    }

    let nonce_be = u64_to_be_32(parsed.nonce);
    let (prep_pda, prep_bump) =
        Pubkey::find_program_address(&[b"prep", &nonce_be], &crate::ID);
    require_keys_eq!(ctx.accounts.prepared.key(), prep_pda, ErrorCode::MemoParseError);
    require!(
        ctx.accounts.prepared.data_is_empty(),
        ErrorCode::NullifierAlreadyUsed
    );

    let prep_rent = Rent::get()?.minimum_balance(PreparedTx::LEN);
    system_program::create_account(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            system_program::CreateAccount {
                from: ctx.accounts.escrow.to_account_info(),
                to:   ctx.accounts.prepared.to_account_info(),
            },
            &[
                &[b"escrow", &[ctx.accounts.state.escrow_bump]],
                &[b"prep", &nonce_be, &[prep_bump]],
            ],
        ),
        prep_rent,
        PreparedTx::LEN as u64,
        &crate::ID,
    )?;
    {
        let mut data = ctx.accounts.prepared.try_borrow_mut_data()?;
        data[0..8].copy_from_slice(&PreparedTx::DISCRIMINATOR);
        data[8]  = prep_bump;
        data[9]  = 0;
        data[10..18].copy_from_slice(&parsed.nonce.to_le_bytes());
        data[18..50].copy_from_slice(&ctx.accounts.recipient.key().to_bytes());
        data[50..82].copy_from_slice(&ctx.accounts.relayer.key().to_bytes());
        data[82..90].copy_from_slice(&to_recipient.to_le_bytes());
        data[90..98].copy_from_slice(&to_relayer.to_le_bytes());
    }

    remaining_idx = 0;

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

    emit!(PreparedWithdraw {
        nonce: parsed.nonce,
        recipient: ctx.accounts.recipient.key(),
        relayer: ctx.accounts.relayer.key(),
        to_recipient,
        to_relayer,
    });

    Ok(())
}

pub fn execute_prepared_withdraw(ctx: Context<ExecutePrepared>) -> Result<()> {
    let authorized_relayer = Pubkey::from_str(AUTHORIZED_RELAYER)
        .map_err(|_| ErrorCode::Unauthorized)?;
    require_keys_eq!(
        ctx.accounts.relayer.key(),
        authorized_relayer,
        ErrorCode::Unauthorized
    );

    let data = ctx.accounts.prepared.try_borrow_data()?;
    require!(
        &data[0..8] == PreparedTx::DISCRIMINATOR,
        ErrorCode::MemoParseError
    );
    let _bump = data[8];
    let executed = data[9] == 1;
    require!(!executed, ErrorCode::NullifierAlreadyUsed);
    let mut off = 10usize;

    let mut nonce_le = [0u8; 8];
    nonce_le.copy_from_slice(&data[off..off + 8]); off += 8;
    let nonce = u64::from_le_bytes(nonce_le);

    let mut recip = [0u8; 32];
    recip.copy_from_slice(&data[off..off + 32]); off += 32;
    let recipient = Pubkey::new_from_array(recip);

    let mut rel = [0u8; 32];
    rel.copy_from_slice(&data[off..off + 32]); off += 32;
    let relayer = Pubkey::new_from_array(rel);

    let mut to_recipient_le = [0u8; 8];
    to_recipient_le.copy_from_slice(&data[off..off + 8]); off += 8;
    let to_recipient = u64::from_le_bytes(to_recipient_le);

    let mut to_relayer_le = [0u8; 8];
    to_relayer_le.copy_from_slice(&data[off..off + 8]);
    let to_relayer = u64::from_le_bytes(to_relayer_le);

    drop(data);

    let total_payout = to_recipient
        .checked_add(to_relayer)
        .ok_or(ErrorCode::Overflow)?;

    let nonce_be = u64_to_be_32(nonce);
    let (expected, _) = Pubkey::find_program_address(&[b"prep", &nonce_be], &crate::ID);
    require_keys_eq!(expected, ctx.accounts.prepared.key(), ErrorCode::MemoParseError);

    require_keys_eq!(recipient, ctx.accounts.recipient.key(), ErrorCode::MemoParseError);
    require_keys_eq!(relayer,   ctx.accounts.relayer.key(),   ErrorCode::MemoParseError);

    require!(
        ctx.accounts.pool.lamports() >= total_payout,
        ErrorCode::InsufficientPoolFunds
    );

    system_program::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.pool.to_account_info(),
                to:   ctx.accounts.recipient.to_account_info(),
            },
            &[
                &[b"pool",   &[ctx.accounts.state.pool_bump]],
                &[b"escrow", &[ctx.accounts.state.escrow_bump]],
            ],
        ),
        to_recipient,
    )?;

    system_program::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.pool.to_account_info(),
                to:   ctx.accounts.relayer.to_account_info(),
            },
            &[
                &[b"pool",   &[ctx.accounts.state.pool_bump]],
                &[b"escrow", &[ctx.accounts.state.escrow_bump]],
            ],
        ),
        to_relayer,
    )?;

    ctx.accounts.state.total_withdrawn = ctx
        .accounts
        .state
        .total_withdrawn
        .checked_add(total_payout)
        .ok_or(ErrorCode::Overflow)?;

    require!(
        ctx.accounts.pool.lamports()
            + RENT_WIGGLE
            >= ctx.accounts.state.total_deposited.saturating_sub(ctx.accounts.state.total_withdrawn),
        ErrorCode::PoolInvariantViolation
    );

    {
        let mut d = ctx.accounts.prepared.try_borrow_mut_data()?;
        d[9] = 1;
    }
    let lamports = ctx.accounts.prepared.to_account_info().lamports();
    **ctx.accounts
        .prepared
        .to_account_info()
        .try_borrow_mut_lamports()? -= lamports;
    **ctx.accounts
        .escrow
        .to_account_info()
        .try_borrow_mut_lamports()? += lamports;
    let mut data_mut = ctx.accounts.prepared.try_borrow_mut_data()?;
    for b in data_mut.iter_mut() { *b = 0; }

    emit!(ExecutedWithdraw {
        nonce,
        recipient,
        relayer,
        to_recipient,
        to_relayer,
    });

    Ok(())
}

#[derive(Accounts)]
pub struct PrepareWithdraw<'info> {
    #[account(mut, seeds = [b"state"], bump = state.bump)]
    pub state: Account<'info, GlobalState>,

    /// CHECK: pool (may receive extAmountIn and later pay out)
    #[account(mut, seeds = [b"pool"], bump = state.pool_bump)]
    pub pool: UncheckedAccount<'info>,

    #[account(mut)]
    pub recipient: SystemAccount<'info>,

    /// CHECK: relayer who will later execute & receive tip
    #[account()]
    pub relayer: UncheckedAccount<'info>,

    /// CHECK: ESCROW pays rent for PDAs
    #[account(mut, seeds = [b"escrow"], bump = state.escrow_bump)]
    pub escrow: UncheckedAccount<'info>,

    /// CHECK: PreparedTx PDA (created here)
    #[account(mut)]
    pub prepared: UncheckedAccount<'info>,

    #[account(mut)]
    pub signer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExecutePrepared<'info> {
    #[account(mut, seeds = [b"state"], bump = state.bump)]
    pub state: Account<'info, GlobalState>,

    /// CHECK: pool pays out
    #[account(mut, seeds = [b"pool"], bump = state.pool_bump)]
    pub pool: UncheckedAccount<'info>,

    #[account(mut)]
    pub recipient: SystemAccount<'info>,

    /// CHECK: relayer receives tip
    #[account(mut)]
    pub relayer: UncheckedAccount<'info>,

    /// CHECK: escrow receives closed account rent
    #[account(mut, seeds = [b"escrow"], bump = state.escrow_bump)]
    pub escrow: UncheckedAccount<'info>,

    /// CHECK: the immutable prepared withdrawal PDA
    #[account(mut)]
    pub prepared: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct PreparedWithdraw {
    pub nonce: u64,
    pub recipient: Pubkey,
    pub relayer: Pubkey,
    pub to_recipient: u64,
    pub to_relayer: u64,
}

#[event]
pub struct ExecutedWithdraw {
    pub nonce: u64,
    pub recipient: Pubkey,
    pub relayer: Pubkey,
    pub to_recipient: u64,
    pub to_relayer: u64,
}
