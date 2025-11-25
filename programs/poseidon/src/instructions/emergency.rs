use anchor_lang::prelude::*;
use anchor_lang::system_program;
use crate::state::{GlobalState, NoteRecord, NullifierFlag};
use crate::errors::ErrorCode;
use crate::constants::{ROOT_HISTORY, RENT_WIGGLE};

pub fn emergency_withdraw(
    ctx: Context<EmergencyWithdraw>,
    commitment: [u8; 32],
) -> Result<()> {
    // Manually deserialize NoteRecord
    let note_data = ctx.accounts.note.try_borrow_data()?;
    require!(&note_data[0..8] == &NoteRecord::DISCRIMINATOR, ErrorCode::MemoParseError);
    
    let note_index = u32::from_le_bytes(note_data[9..13].try_into().unwrap());
    let stored_commitment = <[u8; 32]>::try_from(&note_data[13..45]).unwrap();
    let depositor = Pubkey::new_from_array(note_data[45..77].try_into().unwrap());
    let amount = u64::from_le_bytes(note_data[77..85].try_into().unwrap());
    
    // Verify commitment matches
    require!(stored_commitment == commitment, ErrorCode::MemoParseError);
    
    require!(
        depositor == ctx.accounts.depositor.key(),
        ErrorCode::Unauthorized
    );

    let state = &ctx.accounts.state;
    
    // The note was inserted at note_index. After ROOT_HISTORY more deposits,
    // its root would be pushed out. Check if current index is far enough ahead.
    let current_index = state.next_index;
    let deposits_since_note = current_index.saturating_sub(note_index);
    
    require!(
        deposits_since_note > ROOT_HISTORY as u32,
        ErrorCode::RootStillValid
    );

    drop(note_data);

    use solana_program::keccak;
    let mut nullifier_input = Vec::with_capacity(64);
    nullifier_input.extend_from_slice(&commitment);
    nullifier_input.extend_from_slice(b"emergency_nullifier_v1______0000");
    let nullifier = keccak::hash(&nullifier_input).to_bytes();

    let (nullifier_pda, nullifier_bump) = 
        Pubkey::find_program_address(&[b"null", &nullifier], &crate::ID);
    
    require_keys_eq!(
        ctx.accounts.nullifier_flag.key(),
        nullifier_pda,
        ErrorCode::MissingNullifierPda
    );

    let nullifier_ai = &ctx.accounts.nullifier_flag;
    if nullifier_ai.data_len() == 0 {
        let lamports = Rent::get()?.minimum_balance(NullifierFlag::LEN);
        system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::CreateAccount {
                    from: ctx.accounts.escrow.to_account_info(),
                    to: nullifier_ai.to_account_info(),
                },
                &[
                    &[b"escrow", &[ctx.accounts.state.escrow_bump]],
                    &[b"null", nullifier.as_ref(), &[nullifier_bump]],
                ],
            ),
            lamports,
            NullifierFlag::LEN as u64,
            &crate::ID,
        )?;
        let mut data = nullifier_ai.try_borrow_mut_data()?;
        data[0..8].copy_from_slice(&NullifierFlag::DISCRIMINATOR);
        data[8] = nullifier_bump;
    } else {
        return Err(ErrorCode::NullifierAlreadyUsed.into());
    }

    let pool_seeds: &[&[u8]] = &[b"pool", &[ctx.accounts.state.pool_bump]];
    system_program::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.pool.to_account_info(),
                to: ctx.accounts.depositor.to_account_info(),
            },
            &[pool_seeds],
        ),
        amount,
    )?;

    // 6) Update accounting
    let state = &mut ctx.accounts.state;
    state.total_withdrawn = state
        .total_withdrawn
        .checked_add(amount)
        .ok_or(ErrorCode::Overflow)?;

    // 7) Verify accounting invariant (pool must remain >= deposits - withdrawals)
    require!(
        ctx.accounts.pool.lamports()
            + RENT_WIGGLE
            >= state.total_deposited.saturating_sub(state.total_withdrawn),
        ErrorCode::PoolInvariantViolation
    );

    emit!(EmergencyWithdrawal {
        commitment,
        nullifier,
        depositor,
        amount,
    });

    Ok(())
}

#[derive(Accounts)]
#[instruction(commitment: [u8; 32])]
pub struct EmergencyWithdraw<'info> {
    #[account(mut, seeds = [b"state"], bump = state.bump)]
    pub state: Account<'info, GlobalState>,

    /// CHECK: pool pays out to original depositor
    #[account(mut, seeds = [b"pool"], bump = state.pool_bump)]
    pub pool: UncheckedAccount<'info>,

    /// CHECK: escrow pays rent for nullifier PDA
    #[account(mut, seeds = [b"escrow"], bump = state.escrow_bump)]
    pub escrow: UncheckedAccount<'info>,

    /// CHECK: manually deserialize NoteRecord
    #[account(seeds = [b"note", commitment.as_ref()], bump)]
    pub note: UncheckedAccount<'info>,

    /// CHECK: nullifier PDA (created here, derived from commitment)
    #[account(mut)]
    pub nullifier_flag: UncheckedAccount<'info>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct EmergencyWithdrawal {
    pub commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub depositor: Pubkey,
    pub amount: u64,
}
