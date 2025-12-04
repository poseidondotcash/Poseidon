use anchor_lang::prelude::*;
use anchor_lang::system_program;
use crate::state::{GlobalState, NoteRecord, NullifierFlag, PreparedTx};
use crate::errors::ErrorCode;

pub fn delete_orphaned_nullifier(
    ctx: Context<DeleteOrphanedNullifier>,
    commitment: [u8; 32],
    nullifier: [u8; 32],
) -> Result<()> {
    let note_data = ctx.accounts.note.try_borrow_data()?;
    require!(&note_data[0..8] == &NoteRecord::DISCRIMINATOR, ErrorCode::MemoParseError);
    
    let stored_commitment = <[u8; 32]>::try_from(&note_data[13..45]).unwrap();
    let depositor = Pubkey::new_from_array(note_data[45..77].try_into().unwrap());
    
    require!(stored_commitment == commitment, ErrorCode::MemoParseError);
    drop(note_data);
    
    require!(
        depositor == ctx.accounts.depositor.key(),
        ErrorCode::Unauthorized
    );
    
    let prepared_tx_data = ctx.accounts.prepared_tx.try_borrow_data()?;
    let prepared_tx_exists = prepared_tx_data.len() >= 8 
        && &prepared_tx_data[0..8] == PreparedTx::DISCRIMINATOR;
    
    require!(!prepared_tx_exists, ErrorCode::WithdrawalInProgress);
    drop(prepared_tx_data);
    
    let (nullifier_pda, _bump) = 
        Pubkey::find_program_address(&[b"null", &nullifier], &crate::ID);
    
    require_keys_eq!(
        ctx.accounts.nullifier_flag.key(),
        nullifier_pda,
        ErrorCode::MissingNullifierPda
    );
    
    let nullifier_data = ctx.accounts.nullifier_flag.try_borrow_data()?;
    require!(
        nullifier_data.len() >= 8 && &nullifier_data[0..8] == NullifierFlag::DISCRIMINATOR,
        ErrorCode::NullifierNotFound
    );
    drop(nullifier_data);
    
    let nullifier_lamports = ctx.accounts.nullifier_flag.lamports();
    
    **ctx.accounts.nullifier_flag.to_account_info().try_borrow_mut_lamports()? -= nullifier_lamports;
    **ctx.accounts.depositor.to_account_info().try_borrow_mut_lamports()? += nullifier_lamports;
    
    ctx.accounts.nullifier_flag.to_account_info().resize(0)?;
    ctx.accounts.nullifier_flag.to_account_info().assign(&system_program::ID);
    
    emit!(OrphanedNullifierDeleted {
        commitment,
        nullifier,
        depositor,
    });
    
    msg!("Orphaned nullifier deleted - note can now be withdrawn");
    
    Ok(())
}

#[derive(Accounts)]
#[instruction(commitment: [u8; 32], nullifier: [u8; 32])]
pub struct DeleteOrphanedNullifier<'info> {
    #[account(seeds = [b"state"], bump = state.bump)]
    pub state: Account<'info, GlobalState>,
    
    /// CHECK: manually deserialize NoteRecord to verify it still exists
    #[account(seeds = [b"note", commitment.as_ref()], bump)]
    pub note: UncheckedAccount<'info>,
    
    /// CHECK: manually check PreparedTx to ensure no withdrawal in progress
    #[account(seeds = [b"prepared_tx", depositor.key().as_ref()], bump)]
    pub prepared_tx: UncheckedAccount<'info>,
    
    /// CHECK: nullifier PDA to delete (must exist and match derivation)
    #[account(mut, seeds = [b"null", nullifier.as_ref()], bump)]
    pub nullifier_flag: UncheckedAccount<'info>,
    
    /// Original depositor - only they can delete their orphaned nullifier
    #[account(mut)]
    pub depositor: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[event]
pub struct OrphanedNullifierDeleted {
    pub commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub depositor: Pubkey,
}
