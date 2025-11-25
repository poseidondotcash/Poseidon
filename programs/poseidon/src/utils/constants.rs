pub const TREE_DEPTH: usize = 26;
pub const ROOT_HISTORY: usize = 100;
pub const RELAYER_FEE_BPS: u64 = 15;
pub const BPS_DENOM: u64 = 10_000;
pub const RELAYER_GAS_BUFFER_LAMPORTS: u64 = 5_000_000;
pub const MAX_FEE_BPS: u64 = 500;
pub const RENT_WIGGLE: u64 = 1_000_000;
pub const MAX_INS: usize = 6;
pub const MAX_OUTS: usize = 6;

pub const BN254_P_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x4a, 0x2a, 0x77, 0x9c, 0x59, 0xbd, 0xce,
    0xe8, 0x3b, 0xbf, 0xf2, 0xf9, 0x7a, 0x3d, 0xa3
];

pub const ZERO32: [u8; 32] = [0u8; 32];
pub const AUTHORIZED_RELAYER: &str = "8Ty6oaUGbauTp1ZwLNQ2ZCSvRXTC24waFvLD7ctiVnuv";
