use anchor_lang::prelude::*;

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid zk proof")]
    InvalidProof,

    #[msg("Overflow")]
    Overflow,

    #[msg("Merkle tree is full")]
    TreeFull,

    #[msg("Unknown Merkle root")]
    UnknownRoot,

    #[msg("Nullifier already used or withdrawal already executed")]
    NullifierAlreadyUsed,

    #[msg("Expected note PDA not provided")]
    MissingNotePda,

    #[msg("Expected nullifier PDA not provided")]
    MissingNullifierPda,

    #[msg("Expected output note PDA not provided")]
    MissingOutputNotePda,

    #[msg("Output commitments and ciphertexts length mismatch")]
    CiphertextsMismatch,

    #[msg("Malformed withdraw memo")]
    MemoParseError,

    #[msg("Withdrawal amount too small - must cover relayer fee (0.15% + 0.005 SOL)")]
    InsufficientWithdrawalAmount,

    #[msg("Relayer fee exceeds maximum allowed")]
    ExcessiveFee,

    #[msg("Compressed memo: indices must be strictly increasing")]
    InvalidCompressedMemoIndex,

    #[msg("Insufficient pool funds for payout")]
    InsufficientPoolFunds,

    #[msg("Unauthorized access")]
    Unauthorized,

    #[msg("Pool invariant violated: withdrawn exceeds deposited")]
    PoolInvariantViolation,

    #[msg("Root is still valid - use normal withdrawal with zkSNARK proof")]
    RootStillValid,

    #[msg("Invalid public input: field element out of range")]
    InvalidPublicInput,
}
