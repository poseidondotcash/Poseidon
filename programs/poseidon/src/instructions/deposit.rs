use anchor_lang::prelude::*;
use anchor_lang::system_program;
use crate::state::{GlobalState, NoteRecord};
use crate::errors::ErrorCode;
use crate::merkle::insert_leaf;
use crate::constants::RELAYER_GAS_BUFFER_LAMPORTS;

pub fn deposit_with_note<'info>(
    ctx: Context<'_, '_, '_, 'info, DepositWithNote<'info>>,
    amount: u64,
    commitment: [u8; 32],
    ciphertext: Vec<u8>,
) -> Result<()> {
    let note_rent = Rent::get()?.minimum_balance(NoteRecord::len_for(ciphertext.len()));
    let escrow_balance = ctx.accounts.escrow.lamports();
    let target_balance = note_rent
        .checked_add(RELAYER_GAS_BUFFER_LAMPORTS)
        .ok_or(ErrorCode::Overflow)?;
    
    if escrow_balance < target_balance {
        let need = target_balance
            .checked_sub(escrow_balance)
            .ok_or(ErrorCode::Overflow)?;
        
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.depositor.to_account_info(),
                    to: ctx.accounts.escrow.to_account_info(),
                },
            ),
            need,
        )?;
        
        msg!("💰 Topped up escrow by {} lamports (current: {}, target: {})", 
             need, escrow_balance, target_balance);
    }

    system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.depositor.to_account_info(),
                to:   ctx.accounts.pool.to_account_info(),
            },
        ),
        amount,
    )?;

    ctx.accounts.state.total_deposited = ctx
        .accounts
        .state
        .total_deposited
        .checked_add(amount)
        .ok_or(ErrorCode::Overflow)?;

    let (idx, new_root) = insert_leaf(&mut ctx.accounts.state, commitment)?;

    let note_ai_ref = &ctx.accounts.note;
    if note_ai_ref.data_len() == 0 {
        let space = NoteRecord::len_for(ciphertext.len());
        let lamports = Rent::get()?.minimum_balance(space);
        system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::CreateAccount {
                    from: ctx.accounts.escrow.to_account_info(),
                    to:   note_ai_ref.to_account_info(),
                },
                &[
                    &[b"escrow", &[ctx.accounts.state.escrow_bump]],
                    &[b"note", commitment.as_ref(), &[ctx.bumps.note]],
                ],
            ),
            lamports, space as u64, &crate::ID,
        )?;
        let mut data = note_ai_ref.try_borrow_mut_data()?;
        data[0..8].copy_from_slice(&NoteRecord::DISCRIMINATOR);
        data[8] = ctx.bumps.note;
        data[9..13].copy_from_slice(&idx.to_le_bytes());
        data[13..45].copy_from_slice(&commitment);
        data[45..77].copy_from_slice(&ctx.accounts.depositor.key().to_bytes());
        data[77..85].copy_from_slice(&amount.to_le_bytes());
        let len_le: [u8; 4] = (ciphertext.len() as u32).to_le_bytes();
        data[85..89].copy_from_slice(&len_le);
        data[89..89 + ciphertext.len()].copy_from_slice(&ciphertext);
    }

    emit!(NewNote { commitment, index: idx, root: new_root, ciphertext: ciphertext.clone() });
    emit!(RootUpdated { new_root, index: idx });
    emit!(DepositMade {
        depositor: ctx.accounts.depositor.key(),
        amount,
        commitment,
        note_pda: ctx.accounts.note.key(),
        ciphertext,
    });
    Ok(())
}

#[derive(Accounts)]
#[instruction(amount: u64, commitment: [u8; 32])]
pub struct DepositWithNote<'info> {
    #[account(mut, seeds = [b"state"], bump = state.bump)]
    pub state: Account<'info, GlobalState>,

    /// CHECK: pool receives deposit lamports
    #[account(mut, seeds = [b"pool"], bump = state.pool_bump)]
    pub pool: UncheckedAccount<'info>,

    /// CHECK: escrow pays rent for note PDAs
    #[account(mut, seeds = [b"escrow"], bump = state.escrow_bump)]
    pub escrow: UncheckedAccount<'info>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    /// CHECK: Note PDA for commitment
    #[account(mut, seeds = [b"note", commitment.as_ref()], bump)]
    pub note: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct NewNote {
    pub commitment: [u8; 32],
    pub index: u32,
    pub root: [u8; 32],
    pub ciphertext: Vec<u8>,
}

#[event]
pub struct RootUpdated {
    pub new_root: [u8; 32],
    pub index: u32,
}

#[event]
pub struct DepositMade {
    pub depositor: Pubkey,
    pub amount: u64,
    pub commitment: [u8; 32],
    pub note_pda: Pubkey,
    pub ciphertext: Vec<u8>,
}
