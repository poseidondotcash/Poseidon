use anchor_lang::prelude::*;
use anchor_lang::system_program;
use crate::state::{GlobalState, NoteRecord, NullifierFlag};
use crate::errors::ErrorCode;
use crate::constants::RENT_WIGGLE;

pub fn emergency_recover_with_salt(
    ctx: Context<EmergencyRecoverWithSalt>,
    commitment: [u8; 32],
    salt: u64,
) -> Result<()> {
    let note_data = ctx.accounts.note.try_borrow_data().ok();
    let note_exists = note_data
        .as_ref()
        .map(|data| data.len() >= 8 && &data[0..8] == &NoteRecord::DISCRIMINATOR)
        .unwrap_or(false);
    
    if note_exists {
        let note_data = note_data.unwrap();
        let stored_commitment = <[u8; 32]>::try_from(&note_data[13..45]).unwrap();
        let depositor = Pubkey::new_from_array(note_data[45..77].try_into().unwrap());
        let amount = u64::from_le_bytes(note_data[77..85].try_into().unwrap());
        
        require!(stored_commitment == commitment, ErrorCode::MemoParseError);
        require!(depositor == ctx.accounts.depositor.key(), ErrorCode::Unauthorized);
        
        drop(note_data);
        
        {
            use solana_program::keccak;
            
            let mut nullifier_input = Vec::with_capacity(72);
            nullifier_input.extend_from_slice(&commitment);
            nullifier_input.extend_from_slice(b"emergency_recovery_v2_______");
            nullifier_input.extend_from_slice(&salt.to_le_bytes());
            
            let nullifier = keccak::hash(&nullifier_input).to_bytes();
            
            let (nullifier_pda, nullifier_bump) = 
                Pubkey::find_program_address(&[b"null", &nullifier], &crate::ID);
            
            require_keys_eq!(
                ctx.accounts.nullifier_flag.key(),
                nullifier_pda,
                ErrorCode::MissingNullifierPda
            );
            
            let nullifier_ai = &ctx.accounts.nullifier_flag;
            require!(nullifier_ai.data_len() == 0, ErrorCode::NullifierAlreadyUsed);
            
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
        
        update_accounting(&mut ctx.accounts.state, &ctx.accounts.pool, amount)?;
        
        emit!(EmergencyRecovery {
            commitment,
            depositor: ctx.accounts.depositor.key(),
            amount,
            salt,
        });
        
        Ok(())
    } else {
        msg!("⚠️ WARNING: Note PDA doesn't exist. This should only be used if you have proof of ownership.");
        msg!("   Commitment: {:?}", commitment);
        msg!("   Depositor: {}", ctx.accounts.depositor.key());
        msg!("   This recovery path requires off-chain verification that funds are legitimately stuck.");
        
        Err(ErrorCode::NoteNotFound.into())
    }
}

pub fn emergency_recover_orphaned(
    ctx: Context<EmergencyRecoverOrphaned>,
    commitment: [u8; 32],
    amount: u64,
    salt: u64,
    depositor_override: Pubkey, // Explicit depositor since we can't verify from note
) -> Result<()> {
    require_keys_eq!(
        ctx.accounts.admin.key(),
        ctx.accounts.state.admin,
        ErrorCode::Unauthorized
    );
    
    let note_data = ctx.accounts.note.try_borrow_data().ok();
    let note_exists = note_data
        .as_ref()
        .map(|data| data.len() >= 8 && &data[0..8] == &NoteRecord::DISCRIMINATOR)
        .unwrap_or(false);
    
    require!(!note_exists, ErrorCode::NoteStillExists);
    
    msg!("⚠️ ADMIN EMERGENCY RECOVERY: Recovering orphaned funds");
    msg!("   Admin: {}", ctx.accounts.admin.key());
    msg!("   Commitment: {:?}", commitment);
    msg!("   Amount: {} lamports ({} SOL)", amount, amount as f64 / 1_000_000_000.0);
    msg!("   Recipient: {}", depositor_override);
    msg!("   Salt: {}", salt);
    
    let pool_balance = ctx.accounts.pool.lamports();
    require!(
        pool_balance >= amount,
        ErrorCode::InsufficientPoolFunds
    );
    
    {
        use solana_program::keccak;
        
        let mut nullifier_input = Vec::with_capacity(72);
        nullifier_input.extend_from_slice(&commitment);
        nullifier_input.extend_from_slice(b"emergency_recovery_v2_______");
        nullifier_input.extend_from_slice(&salt.to_le_bytes());
        
        let nullifier = keccak::hash(&nullifier_input).to_bytes();
        
        let (nullifier_pda, nullifier_bump) = 
            Pubkey::find_program_address(&[b"null", &nullifier], &crate::ID);
        
        require_keys_eq!(
            ctx.accounts.nullifier_flag.key(),
            nullifier_pda,
            ErrorCode::MissingNullifierPda
        );
        
        let nullifier_ai = &ctx.accounts.nullifier_flag;
        require!(nullifier_ai.data_len() == 0, ErrorCode::NullifierAlreadyUsed);
        
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
    }
    
    let pool_seeds: &[&[u8]] = &[b"pool", &[ctx.accounts.state.pool_bump]];
    system_program::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.pool.to_account_info(),
                to: ctx.accounts.recipient.to_account_info(),
            },
            &[pool_seeds],
        ),
        amount,
    )?;
    
    update_accounting(&mut ctx.accounts.state, &ctx.accounts.pool, amount)?;
    
    emit!(EmergencyRecovery {
        commitment,
        depositor: depositor_override,
        amount,
        salt,
    });
    
    msg!("✅ Admin recovery successful!");
    
    Ok(())
}

fn update_accounting(
    state: &mut GlobalState,
    pool: &UncheckedAccount,
    amount: u64,
) -> Result<()> {
    state.total_withdrawn = state
        .total_withdrawn
        .checked_add(amount)
        .ok_or(ErrorCode::Overflow)?;
    
    require!(
        pool.lamports() + RENT_WIGGLE >= state.total_deposited.saturating_sub(state.total_withdrawn),
        ErrorCode::PoolInvariantViolation
    );
    
    Ok(())
}

#[derive(Accounts)]
#[instruction(commitment: [u8; 32], salt: u64)]
pub struct EmergencyRecoverWithSalt<'info> {
    #[account(mut, seeds = [b"state"], bump = state.bump)]
    pub state: Account<'info, GlobalState>,

    /// CHECK: pool pays out to original depositor
    #[account(mut, seeds = [b"pool"], bump = state.pool_bump)]
    pub pool: UncheckedAccount<'info>,

    /// CHECK: escrow pays rent for nullifier PDA
    #[account(mut, seeds = [b"escrow"], bump = state.escrow_bump)]
    pub escrow: UncheckedAccount<'info>,

    /// CHECK: note PDA (may or may not exist) - no seeds constraint to support legacy PDAs
    pub note: UncheckedAccount<'info>,

    /// CHECK: salted nullifier PDA (created here)
    #[account(mut)]
    pub nullifier_flag: UncheckedAccount<'info>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(commitment: [u8; 32], amount: u64, salt: u64, depositor_override: Pubkey)]
pub struct EmergencyRecoverOrphaned<'info> {
    #[account(mut, seeds = [b"state"], bump = state.bump)]
    pub state: Account<'info, GlobalState>,

    /// CHECK: pool pays out to recipient
    #[account(mut, seeds = [b"pool"], bump = state.pool_bump)]
    pub pool: UncheckedAccount<'info>,

    /// CHECK: escrow pays rent for nullifier PDA
    #[account(mut, seeds = [b"escrow"], bump = state.escrow_bump)]
    pub escrow: UncheckedAccount<'info>,

    /// CHECK: note PDA (should NOT exist for orphaned case) - no seeds constraint to support legacy PDAs
    pub note: UncheckedAccount<'info>,

    /// CHECK: salted nullifier PDA (created here)
    #[account(mut)]
    pub nullifier_flag: UncheckedAccount<'info>,

    /// Admin must sign for orphaned recovery (cannot verify depositor without note)
    #[account(mut)]
    pub admin: Signer<'info>,

    /// CHECK: Recipient of the recovered funds
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct EmergencyRecovery {
    pub commitment: [u8; 32],
    pub depositor: Pubkey,
    pub amount: u64,
    pub salt: u64,
}
