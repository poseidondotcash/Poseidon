use anchor_lang::prelude::*;
use crate::state::NoteRecord;
use crate::errors::ErrorCode;

pub fn fetch_note(ctx: Context<FetchNote>, commitment: [u8; 32]) -> Result<()> {
    let data = ctx.accounts.note.try_borrow_data()?;
    require!(&data[0..8] == &NoteRecord::DISCRIMINATOR, ErrorCode::MemoParseError);
    
    let index = u32::from_le_bytes(data[9..13].try_into().unwrap());
    let ciphertext_len = u32::from_le_bytes(data[85..89].try_into().unwrap()) as usize;
    let ciphertext = data[89..89 + ciphertext_len].to_vec();
    
    emit!(NoteFetched {
        commitment,
        index,
        ciphertext,
    });
    Ok(())
}

#[derive(Accounts)]
#[instruction(commitment: [u8; 32])]
pub struct FetchNote<'info> {
    /// CHECK: manually deserialize NoteRecord
    #[account(seeds = [b"note", commitment.as_ref()], bump)]
    pub note: UncheckedAccount<'info>,
}

#[event]
pub struct NoteFetched {
    pub commitment: [u8; 32],
    pub index: u32,
    pub ciphertext: Vec<u8>,
}
