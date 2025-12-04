```
 ____                 _     _            
|  _ \ ___  ___  ___(_) __| | ___  _ __  
| |_) / _ \/ __|/ _ \ |/ _` |/ _ \| '_ \ 
|  __/ (_) \__ \  __/ | (_| | (_) | | | |
|_|   \___/|___/\___|_|\__,_|\___/|_| |_|
                                          
Zero-Knowledge Privacy Protocol on Solana
```

# Poseidon

A production-grade zero-knowledge privacy protocol on Solana using zkSNARKs (Groth16) and Poseidon Merkle trees. Enables fully private deposits and withdrawals with unlinkable change notes.

## Security Model

### Zero-Knowledge Proofs
- **Groth16 zkSNARK** verification on-chain using BN254 curve
- Proves note ownership and transaction validity WITHOUT revealing:
  - Input amounts or balances
  - Note owners
  - Transaction graph (unlinkable)
- Merkle root validation ensures notes exist in commitment tree
- Nullifier system prevents double-spending (critical security invariant)

### Cryptographic Primitives
- **Poseidon Hash**: SNARK-friendly hash function for Merkle tree (matches circuit)
- **BN254 Field Arithmetic**: Scalar field operations for proof verification
- **Sparse Merkle Tree**: Optimized tree with 2^26 capacity (~67 million notes)
- **Ciphertext Storage**: Encrypted note data for recovery (optional)

### Fee Structure & Relayer Economics

The relayer service operator provides critical infrastructure and receives compensation for the following services:

- **Relayer Fee**: 0.15% (15 basis points) + 0.005 SOL gas buffer

- **Maximum Fee Cap**: 5% (MAX_FEE_BPS = 500)
- **Fee Calculation**: `relayer_fee = (withdrawal_amount * 15 / 10000) + 5_000_000 lamports`

**Economic Justification:**
1. **Transaction Costs**: Relayer subsidizes all on-chain transaction fees
2. **Infrastructure Operations**: Maintains WebSocket server, RPC endpoints, and proof verification systems
3. **Privacy Service**: Provides sender-recipient unlinkability through transaction relay
4. **System Maintenance**: Ongoing server operations, monitoring infrastructure, and security patches
5. **Liquidity Risk**: Pool management and protection against MEV extraction attempts

**On-Chain Enforcement:**
- Fee calculation occurs prior to proof verification ensuring transparency
- Maximum fee threshold enforced via MAX_FEE_BPS constant
- Pool invariants cryptographically enforced: `total_deposited >= total_withdrawn`
- Authorized relayer enforced via public key whitelist validation

### On-Chain Security Invariants

#### 1. Double-Spend Prevention
```rust
// Each nullifier can only be used ONCE
NullifierFlag PDA at [b"null", nullifier]
// Attempting to reuse triggers: ErrorCode::NullifierAlreadyUsed
```

#### 2. Pool Accounting
```rust
// Critical invariant checked on EVERY withdrawal
require!(total_deposited >= total_withdrawn, PoolInvariantViolation);
require!(pool.lamports() >= payout, InsufficientPoolFunds);
```

#### 3. Merkle Root Validity
- Root history buffer (1000 most recent roots)
- Prevents expired proof attacks
- Users have flexible proof generation window

#### 4. Amount Conservation
```circom
// Join-split invariant enforced in circuit
(Σ inBalance) + extAmountIn === (Σ outAmount) + publicAmount
```

#### 5. Range Checks
```circom
// All amounts validated as 64-bit unsigned integers
RangeCheckAmount(64) for ALL balances and amounts
// Prevents overflow and negative values
```

#### 6. Nullifier Binding
```circom
// Nullifier computed deterministically from secret + nonce
nullifier = Poseidon(receiverViewPriv, inSpendNonce[i])
// Cannot forge without knowing the secret
```

### Attack Mitigations

| Attack Vector | Mitigation |
|--------------|------------|
| Double-spending | Nullifier flags (permanent on-chain markers) |
| Merkle proof forgery | Groth16 verification + root history validation |
| Amount overflow | Checked arithmetic everywhere, circuit range checks |
| Pool drainage | Strict accounting invariants, pre-transfer balance checks |
| Replay attacks | Two-phase withdrawal with nonce-based PDAs |
| MEV/Front-running | PreparedTx PDA locks in recipient/amounts |
| Proof malleability | Public inputs bound to transaction context |
| TOCTOU (time-of-check) | Pool balance verified BEFORE transfers |
| Compressed memo exploits | Strictly increasing index validation |
| Unauthorized relayer | Whitelist check in prepare_withdraw |

## Architecture

### Circuit Generation with circom-chan
This project uses [circom-chan](https://github.com/Monero-Chan-Foundation/circom-chan) for circuit generation:

```bash
# Clone and setup circom-chan
git clone https://github.com/Monero-Chan-Foundation/circom-chan.git
cd circom-chan

# Create groth16_beast.sh (see Testing & Development section)
# Then run:
./groth16_beast.sh

# Outputs:
# - circuits/poseidon_main.circom
# - circuits/poseidon_main.wasm
# - circuits/privw_final.zkey
# - circuits/privw_vk.json
```

### Program Structure
```
programs/poseidon/src/
├── lib.rs              # Entry point, program definition
├── vk.rs               # Verifying key (auto-generated from circom-chan output)
├── instructions/       # Transaction handlers
│   ├── init.rs         # Initialize global state
│   ├── deposit.rs      # Deposit funds into pool
│   ├── withdraw.rs     # Two-phase withdrawal
│   ├── explosive.rs    # Split withdrawals across multiple wallets
│   ├── fetch.rs        # Query note data
│   ├── emergency.rs    # Emergency recovery (expired roots)
│   ├── recover.rs      # Salted nullifier recovery
│   └── cleanup.rs      # Orphaned nullifier cleanup
└── utils/              # Core utilities
    ├── state.rs        # Account structures
    ├── merkle.rs       # Sparse Merkle tree operations
    ├── verification.rs # Groth16 proof verification
    ├── crypto.rs       # BN254 field arithmetic
    ├── constants.rs    # Program constants
    ├── errors.rs       # Error codes
    └── utils.rs        # Helper functions
```

### Circuit Structure
```
circom-chan/circuits/
├── poseidon_main.circom  # Main join-split circuit
├── merkle.circom                # Merkle path verification
└── utils.circom                 # Range checks, packing
```

**Note:** Circuits are generated using `circom-chan` tool with the `groth16_beast.sh` script.

**Circuit Parameters:**
- `nIns = 6`: Maximum input notes
- `nOuts = 6`: Maximum output notes  
- `depth = 26`: Merkle tree depth (MUST match on-chain TREE_DEPTH)

**Public Signals (19 total):**
1. `merkleRoot` (1) - Global tree root
2. `inputNullifier[6]` (6) - Prevents double-spend
3. `destLimbs[4]` (4) - Recipient address (4×u64)
4. `outputCommitment[6]` (6) - New note commitments
5. `publicAmount` (1) - Amount leaving pool
6. `extAmountIn` (1) - Amount entering pool (top-up)

### State Accounts

#### GlobalState
```rust
pub struct GlobalState {
    pub admin: Pubkey,              // Program authority
    pub bump: u8,                   // PDA bump seeds
    pub escrow_bump: u8,
    pub pool_bump: u8,
    pub next_index: u32,            // Next leaf index
    pub current_root: [u8; 32],     // Current Merkle root
    pub root_history_idx: u8,       // Circular buffer index
    pub zeroes: Vec<u8>,            // Tree zero values
    pub filled_subtrees: Vec<u8>,   // Optimization for insertions
    pub root_history: Vec<u8>,      // Last 1000 roots
    pub total_deposited: u64,       // Accounting
    pub total_withdrawn: u64,
}
```

**PDA Seeds:**
- State: `[b"state"]`
- Pool: `[b"pool"]` (holds all deposited lamports)
- Escrow: `[b"escrow"]` (pays rent for PDAs)

#### NoteRecord
```rust
pub struct NoteRecord {
    pub bump: u8,
    pub index: u32,                 // Position in tree
    pub commitment: [u8; 32],       // Poseidon(amount, nonce)
    pub depositor: Pubkey,          // For emergency recovery
    pub amount: u64,                // Plaintext (for deposits only)
    pub ciphertext_len: u32,
    pub ciphertext: Vec<u8>,        // Encrypted note data
}
```

**PDA Seeds:**
- Deposit notes: `[b"note", commitment]`
- Withdraw change notes: `[b"note", tree_index_be]`

#### PreparedTx (Two-Phase Withdrawal)
```rust
pub struct PreparedTx {
    pub bump: u8,
    pub executed: bool,             // Replay protection
    pub nonce: u64,                 // Unique transaction ID
    pub recipient: Pubkey,          // Locked in during prepare
    pub relayer: Pubkey,
    pub to_recipient: u64,
    pub to_relayer: u64,
}
```

**PDA Seeds:** `[b"prep", nonce_be]`

#### NullifierFlag
```rust
pub struct NullifierFlag {
    pub bump: u8,
}
```

**PDA Seeds:** `[b"null", nullifier]`

#### ExplosiveWithdrawal
```rust
pub struct ExplosiveWithdrawal {
    pub bump: u8,
    pub executed: bool,
    pub nonce: u64,
    pub final_recipient: Pubkey,
    pub relayer: Pubkey,
    pub total_amount: u64,
    pub relayer_fee: u64,
    pub num_receivers: u8,
    pub transfers_completed: u16,      // Bitmask tracking completed transfers
    pub intermediate_wallets: [Pubkey; MAX_EXPLOSIVE_RECEIVERS],
    pub split_amounts: [u64; MAX_EXPLOSIVE_RECEIVERS],
    pub created_slot: u64,
}
```

**PDA Seeds:** `[b"explosive", nonce_be]`

## Transaction Flow

### Deposit
```
1. User invokes deposit_with_note(amount, commitment, ciphertext)
2. Lamport transfer: user_account → pool_pda
3. Commitment inserted into sparse Merkle tree at next_index
4. NoteRecord PDA created (rent paid by escrow_pda)
5. Tree index assigned and stored in ledger for withdrawal
6. Events emitted: NewNote, RootUpdated, DepositMade
```

**Client Responsibilities:**
- Generate random note nonce (256-bit)
- Compute commitment: Poseidon(balance, noteNonce)
- Encrypt note data with view key
- Store memo file and tree index in local ledger

### Withdrawal (Two-Phase)

#### Phase 1: Prepare
```
1. Client generates zkSNARK proof off-chain using WASM/ZKEY
2. Client sends memo to relayer via WebSocket
3. Relayer calls prepare_withdraw_via_memo(memo)
4. Program verifies Groth16 proof with public inputs:
   - merkleRoot (validates against root history)
   - inputNullifier[6] (prevents double-spend)
   - destLimbs[4] (recipient address binding)
   - outputCommitment[6] (change notes)
   - publicAmount (withdrawal amount)
   - extAmountIn (pool top-up, if any)
5. Fee calculation: relayer_fee = (amount × 15 / 10000) + 5_000_000
6. Create NullifierFlag PDAs for each input (marks notes as spent)
7. Create NoteRecord PDAs for non-zero output commitments (change)
8. Create PreparedTx PDA (locks recipient, amounts, nonce)
```

#### Phase 2: Execute
```
1. Relayer calls execute_prepared_withdraw()
2. Load PreparedTx PDA, verify not executed
3. Verify relayer authorization (whitelist check)
4. Transfer: pool → recipient (to_recipient amount)
5. Transfer: pool → relayer (to_relayer fee)
6. Mark PreparedTx as executed (replay protection)
7. Update accounting: total_withdrawn += payout
8. Validate pool invariant: total_deposited >= total_withdrawn
```

**Design Rationale:**
- **Atomic Separation**: Proof verification isolated from fund transfers
- **MEV Resistance**: Recipient and amounts immutably committed in PreparedTx PDA
- **Batch Optimization**: Multiple prepared transactions executable in single block
- **Fault Tolerance**: Failed execution retryable without re-verification

### Explosive Withdrawals (Multi-Hop Privacy Mixing)

Explosive withdrawals enhance privacy by splitting a withdrawal across multiple intermediate wallets with random amounts before final bundling to the recipient.

#### Architecture
```
zkSNARK Withdrawal → Intermediate Wallet 1 (random %)
                  → Intermediate Wallet 2 (random %)
                  → ...
                  → Intermediate Wallet N (remainder)
                  
[Wait for confirmations]

Bundler: Intermediate Wallets → Final Recipient
```

#### Flow
```
1. Client generates zkSNARK proof for total withdrawal amount
2. Client generates first intermediate wallet keypair
3. Relayer receives explosive withdrawal request with:
   - Standard memo (proof + public signals)
   - Number of hops (default: 3)
   - Wallets per hop (default: 10)
   - First intermediate wallet secret key
   - Final recipient address
4. Relayer executes standard prepare + execute to first intermediate wallet
5. For each hop:
   a. Generate N random intermediate wallets
   b. Deterministic random split of funds (5-20% per wallet)
   c. Execute transfers to intermediate wallets
   d. Wait for confirmations
6. Final bundler:
   a. Collect funds from all intermediate wallets
   b. Aggregate to single bundler wallet (highest balance pays fees)
   c. Transfer net amount to final recipient
7. Return detailed hop breakdown to client
```

**Privacy Benefits:**
- **Amount Obfuscation**: Single withdrawal appears as many unrelated small transfers
- **Timing Separation**: Hops executed across different blocks/time periods
- **Graph Breaking**: On-chain analysis cannot link zkSNARK withdrawal to final recipient
- **Mixing Depth**: Configurable hops (1-10) × wallets per hop (1-15)

**Parameters:**
- `MAX_EXPLOSIVE_RECEIVERS = 10`: Maximum intermediate wallets per on-chain instruction
- `--hops`: Number of sequential mixing rounds (default: 3)
- `--wallets`: Intermediate wallets per hop (default: 10)
- Split algorithm: Deterministic pseudo-random using withdrawal nonce as seed

**Example:**
```bash
# 5 hops × 15 wallets = 75 total intermediate wallets
node tests/withdraw_join_split.js \
  --explosive \
  --hops 5 \
  --wallets 15
```

**Security Considerations:**
- First intermediate wallet must be fresh (not linked to user identity)
- Bundler transaction reveals final recipient (trade-off for fund delivery)
- On-chain footprint: 1 zkSNARK prepare/execute + N intermediate transfers + 1 bundler
- Relayer has visibility into full hop graph (trust required)

### Recovery Mechanisms

#### Emergency Withdraw (Expired Notes)
For notes with roots no longer in history (>ROOT_HISTORY deposits old):
```
- Original depositor can recover funds
- Bypasses zkSNARK proof requirement
- WARNING: Links deposit → withdrawal on-chain (breaks privacy)
- Creates nullifier to prevent double-spend
```

#### Salted Nullifier Recovery
For deposits with orphaned nullifiers from failed withdrawals:
```
- Uses salted nullifier to avoid conflicts
- Requires original depositor signature
- Bypasses stuck nullifiers
- Maintains double-spend protection
```

#### Orphaned Nullifier Cleanup
For nullifiers created during failed prepare_withdraw:
```
- Safety checks: Note exists + PreparedTx doesn't exist + Depositor signature
- Deletes orphaned nullifier PDA
- Refunds rent to depositor
- Allows retry of withdrawal
```

### Join-Split Transactions

**Partial Withdrawal (with change):**
```
Inputs:  Note A (1.5 SOL), Note B (0.8 SOL)
Outputs: Change Note (1.2 SOL), empty slots...
Public:  0.1 SOL to recipient
```

**Full Withdrawal (no change):**
```
Inputs:  Note A (1.0 SOL), Note B (2.0 SOL)
Outputs: [empty × 6]
Public:  3.0 SOL to recipient
```

## Memo Format

### Withdrawal Memo Layout
```
Offset  | Field                    | Size    | Notes
--------|--------------------------|---------|------------------
0       | proof_a                  | 64      | Groth16 proof element A
64      | proof_b                  | 128     | Groth16 proof element B
192     | proof_c                  | 64      | Groth16 proof element C
256     | public_amount            | 8       | u64 LE
264     | ext_amount_in            | 8       | u64 LE
272     | nonce                    | 8       | u64 LE (unique tx ID)
280     | n_inputs                 | 4       | u32 LE (≤ 6)
284     | input_nullifiers[0..5]   | 192     | 6 × 32 bytes
476     | flag                     | 1       | 1=full withdraw, 0=compressed
477+    | compressed outputs       | var     | If flag=0: count + [(idx, commit)]
```

#### Compressed Output Format (flag=0)
```
count: u8                          # Number of non-zero outputs
For each non-zero output:
  index: u8                        # Position (0..5)
  commitment: [u8; 32]             # Poseidon(amount, nonce)
```

**Security:** Indices MUST be strictly increasing (prevents duplicate index attacks)

#### Full Withdraw Format (flag=1)
All output commitments set to zeros (no change notes created)

## Testing & Development

### Setup

#### 1. Install circom-chan (Circuit Generator)
```bash
# Clone circom-chan repository
git clone https://github.com/Monero-Chan-Foundation/circom-chan.git
cd circom-chan

# Follow circom-chan setup instructions
# (typically: cargo build --release)
```

#### 2. Create groth16_beast.sh Script
Create `groth16_beast.sh` in the circom-chan root directory:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Resolve repo root to the directory where this script lives
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

CIRCUIT_NAME="basic_privacy_wallet"
OUTDIR="circuits"
CIRCUIT="${OUTDIR}/${CIRCUIT_NAME}.circom"
CIRCOMLIB="${ROOT_DIR}/circomlib"

PTAU0="${OUTDIR}/pot17_0000.ptau"
PTAU1="${OUTDIR}/pot17_0001.ptau"
PTAUF="${OUTDIR}/pot17_final.ptau"
ZKEY0="${OUTDIR}/privw_0000.zkey"
ZKEYF="${OUTDIR}/privw_final.zkey"
VK="${OUTDIR}/privw_vk.json"

# Detect circom binary
if [[ -x "./target/release/circom" ]]; then
  CIRCOM="./target/release/circom"
elif command -v circom >/dev/null 2>&1; then
  CIRCOM="$(command -v circom)"
else
  echo "Error: circom binary not found."
  echo "   Either build it to ./target/release/circom or install it globally (cargo install circom) so 'circom' is in \$PATH."
  exit 1
fi

echo "========================================"
echo "  GROTH16 BEAST MODE START             "
echo "  CIRCOM: $CIRCOM"
echo "  ROOT_DIR: $ROOT_DIR"
echo "========================================"

# 1. Compile circuit
$CIRCOM "$CIRCUIT" --r1cs --wasm --sym -o "$OUTDIR" -l "$CIRCOMLIB"

# 2. PTAU new
npx snarkjs powersoftau new bn128 17 "$PTAU0" -v

# 3. Contribute
npx snarkjs powersoftau contribute "$PTAU0" "$PTAU1" \
  --name="Poseidon Privacy Wallet - Phase 1" \
  -v \
  -e="$(head -c 1024 /dev/urandom | openssl sha256)"

# 4. Prepare phase2
npx snarkjs powersoftau prepare phase2 "$PTAU1" "$PTAUF" -v

# 5. Groth16 setup
npx snarkjs groth16 setup \
  "${OUTDIR}/${CIRCUIT_NAME}.r1cs" \
  "$PTAUF" \
  "$ZKEY0"

# 6. Final contribution
npx snarkjs zkey contribute "$ZKEY0" "$ZKEYF" \
  --name="Poseidon Privacy Wallet - Final Round" \
  -v \
  -e="poseidon_privacy_$(date +%s%N)"

# 7. Verify zkey
npx snarkjs zkey verify \
  "${OUTDIR}/${CIRCUIT_NAME}.r1cs" \
  "$PTAUF" \
  "$ZKEYF"

# 8. Export VK
npx snarkjs zkey export verificationkey "$ZKEYF" "$VK"

echo "========================================"
echo "  POSEIDON WALLET SETUP COMPLETE!      "
echo "  $(date)"
echo "========================================"
echo "Verifier key JSON: $VK"
echo "Proving key: $ZKEYF"
echo "Ready for test proof!"
```

Make it executable:
```bash
chmod +x groth16_beast.sh
```

#### 3. Generate Circuits
```bash
# Run circuit generation
cd circom-chan
./groth16_beast.sh
```

#### 4. Build Poseidon Wallet
```bash
# Install dependencies
cd /path/to/poseidon-wallet
npm install

# Generate verifying key Rust module
node scripts/gen_vk_rs.js \
  --vk /path/to/circom-chan/circuits/privw_vk.json \
  --out programs/poseidon/src/vk.rs

# Build Anchor program
anchor build

# Deploy to devnet
anchor deploy --provider.cluster devnet
```

### Environment Variables
```bash
# Program
PROGRAM_ID="6mXQkJeRkxyjvcrQB7L7Ww2ygK4r3MQXZEwTtxgYoYB9"

# User wallet
PRIVATE_KEY="<base58 secret key>"

# Relayer
RELAYER_SECRET_BASE58="<relayer secret key>"
RPC="https://api.devnet.solana.com"
BIND="127.0.0.1"
PORT="8787"
CU_LIMIT_PREPARE=1300000
CU_LIMIT_EXECUTE=1300000
CU_PRICE_MICROLAMPORTS=0

# Circuit paths (generated by circom-chan)
WASM_PATH="/path/to/circom-chan/circuits/poseidon_main.wasm"
ZKEY_PATH="/path/to/circom-chan/circuits/privw_final.zkey"
```

### Running Tests

#### Comprehensive Test Suite

Run the full test suite with quality checks:

```bash
# Run all tests and quality checks
./test_all.sh

# Options:
./test_all.sh --tests-only      # Run only tests (skip quality checks)
./test_all.sh --quality-only    # Run only quality checks (skip tests)
./test_all.sh --quick           # Skip clean/rebuild
```

**Test Coverage:**
- 53 unit tests across 6 test modules
- Security tests (16 attack vectors)
- Accounting tests (pool invariants)
- Cryptography tests (proof verification)
- State management tests
- Penetration tests
- Integration summary

**Quality Checks:**
- Code formatting (rustfmt)
- Linting (clippy)
- Security audit (cargo-audit)
- Dependency validation
- Release build verification

#### Integration Tests

**Deposit Test:**
```bash
node tests/run_deposits.js \
  --rpc https://api.devnet.solana.com \
  --amount 5000000000
```

**Standard Withdrawal:**
```bash
# Terminal 1: Start relayer
node tests/relayer.js

# Terminal 2: Execute withdrawal
node tests/withdraw_join_split.js \
  --amount 4900000000 \
  --recipient GzVQTNRPGDKRADmQLw5mQNj7B9xMRtJm4bCqJohBJJWn \
  --wasm circuits/poseidon_main.wasm \
  --zkey circuits/privw_final.zkey \
  --rpc https://api.devnet.solana.com \
  --relayer-ws ws://127.0.0.1:8787
```

**Explosive Withdrawal (Enhanced Privacy):**
```bash
# Multi-hop privacy mixing with 5 hops × 15 wallets = 75 intermediate wallets
node tests/withdraw_join_split.js \
  --amount 4900000000 \
  --recipient GzVQTNRPGDKRADmQLw5mQNj7B9xMRtJm4bCqJohBJJWn \
  --wasm circuits/poseidon_main.wasm \
  --zkey circuits/privw_final.zkey \
  --explosive \
  --hops 5 \
  --wallets 15 \
  --rpc https://api.devnet.solana.com \
  --relayer-ws ws://127.0.0.1:8787
```

### Relayer Service

The relayer is a TypeScript WebSocket service that handles withdrawal transactions:

**Key Functions:**
1. Accepts withdrawal requests via WebSocket
2. Validates memo format and extracts public signals
3. Submits `prepare_withdraw_via_memo` transaction
4. Waits for confirmation, then submits `execute_prepared_withdraw`
5. Handles explosive withdrawals with multi-hop mixing
6. Returns transaction signatures to client

**WebSocket Protocol:**

**Standard Withdrawal Request:**
```json
{
  "id": "uuid",
  "type": "withdraw_via_memo_join_split",
  "programId": "6mXQ...",
  "recipient": "8Ty6...",
  "memoPackedBase64": "...",
  "publicSignals": [...],
  "statePda": "...",
  "poolPda": "...",
  "escrowPda": "...",
  "merkleRoot": "..."
}
```

**Explosive Withdrawal Request:**
```json
{
  "id": "uuid",
  "type": "explosive_multi_hop",
  "programId": "6mXQ...",
  "recipient": "8Ty6...",
  "memoPackedBase64": "...",
  "publicSignals": [...],
  "statePda": "...",
  "poolPda": "...",
  "escrowPda": "...",
  "merkleRoot": "...",
  "hops": 5,
  "walletsPerHop": 15,
  "firstIntermediateSecretKey": [...],
  "finalRecipient": "..."
}
```

**Success Response:**
```json
{
  "id": "uuid",
  "ok": true,
  "signature": "5xY7...",
  "preparedSig": "...",
  "hopDetails": [...],
  "totalWallets": 75
}
```

**Error Response:**
```json
{
  "id": "uuid",
  "ok": false,
  "error": "Pool insufficient funds",
  "logs": ["..."]
}
```

**Explosive Withdrawal Features:**
- Automatic multi-hop wallet generation
- Random amount splitting across intermediate wallets
- Sequential hop execution with confirmations
- Final bundler transaction to recipient
- Detailed hop tracking in response

### System Constraints

1. **Circuit Parameters**: Maximum 6 input notes and 6 output notes per transaction
2. **Tree Capacity**: Fixed depth of 26 levels (capacity: 2^26 ≈ 67,108,864 notes)
3. **Root History**: 1000-block validity window for proof generation
4. **Transaction Size**: Legacy transaction format constrains memo to approximately 1232 bytes
5. **Relayer Architecture**: Centralized coordinator (decentralization on roadmap)
6. **Asset Support**: Native SOL only (SPL token integration planned)

### Features

**Current Implementation:**
- Groth16 zkSNARK proof verification on-chain using BN254 curve
- Two-phase withdrawal system (prepare + execute) for MEV resistance
- Join-split transactions supporting up to 6 inputs and 6 outputs
- Explosive withdrawals with multi-hop privacy mixing (up to 10 intermediate wallets per hop)
- Emergency recovery mechanism for expired notes
- Salted nullifier recovery for failed withdrawals
- Orphaned nullifier cleanup for retry capability
- Compressed memo format for transaction size optimization
- Root history buffer (1000 roots) for flexible proof generation window
- Pool invariant validation on every withdrawal
- Comprehensive test suite (53 tests, 6 modules, 16 attack vectors)
- TypeScript relayer with WebSocket API
- Automated quality checks (format, lint, security audit)

**Development Roadmap:**
- [ ] Decentralized relayer network with cryptoeconomic incentives
- [ ] Multi-asset support via SPL token integration
- [ ] Versioned transaction format with address lookup tables
- [ ] Recursive proof aggregation for reduced verification costs
- [ ] Yield-bearing shielded positions (private staking integration)
- [ ] Mobile SDK for React Native environments
- [ ] Browser extension wallet implementation

## Technical Reference

### Dependencies

**Rust:**
- `anchor-lang 0.32.1` - Solana program framework
- `groth16-solana 0.0.3` - BN254 pairing-based verification
- `light-hasher 2.0.0` - Poseidon hash implementation
- `bytemuck 1.14` - Safe byte casting

**JavaScript:**
- `@solana/web3.js ^1.95.8` - Solana client
- `snarkjs ^0.7.5` - zkSNARK proof generation
- `circomlibjs ^0.1.7` - Circom utilities
- `ws ^8.18.0` - WebSocket server (relayer)

**Circom:**
- `circom 2.0.0` - Circuit compiler
- `circomlib` - Standard circuit library
- `circom-chan` - Circuit generation tool using `groth16_beast.sh`

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| TREE_DEPTH | 26 | Merkle tree depth (2^26 capacity) |
| ROOT_HISTORY | 1000 | Number of historical roots |
| RELAYER_FEE_BPS | 15 | 0.15% fee (basis points) |
| RELAYER_GAS_BUFFER | 5_000_000 | 0.005 SOL gas buffer |

| MAX_FEE_BPS | 500 | 5% maximum fee cap |
| MAX_INS | 6 | Maximum input notes |
| MAX_OUTS | 6 | Maximum output notes |
| MAX_EXPLOSIVE_RECEIVERS | 10 | Maximum intermediate wallets for explosive withdrawals |

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 6000 | InvalidProof | zkSNARK proof verification failed |
| 6001 | Overflow | Arithmetic overflow detected |
| 6002 | TreeFull | Merkle tree at max capacity |
| 6003 | UnknownRoot | Root not in history |
| 6004 | NullifierAlreadyUsed | Double-spend attempt |
| 6010 | InsufficientWithdrawalAmount | Payout below minimum |
| 6012 | InsufficientPoolFunds | Pool cannot cover withdrawal |
| 6013 | Unauthorized | Relayer not whitelisted |
| 6014 | PoolInvariantViolation | Accounting invariant broken |
| 6015 | InvalidExplosiveSplit | Explosive withdrawal split validation failed |
| 6016 | MissingIntermediateWallet | Required intermediate wallet account missing |
| 6017 | InvalidIntermediateWallet | Wallet doesn't match explosive withdrawal state |
| 6018 | AlreadyExecuted | Explosive withdrawal already executed |
| 6019 | WithdrawalInProgress | Cannot delete nullifier while PreparedTx exists |
| 6020 | NullifierNotFound | Specified nullifier doesn't exist |
| 6021 | NoteNotFound | Note doesn't exist (may be withdrawn) |
| 6022 | NoteStillExists | Cannot use orphaned recovery when note exists |

## License

MIT License - See LICENSE file for details

## Disclaimer

**THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.**

This is experimental cryptographic software under active development. The authors and contributors disclaim all liability for:
- Financial losses resulting from software defects or cryptographic vulnerabilities
- Privacy breaches arising from implementation errors or operational misuse
- Legal or regulatory compliance in any jurisdiction
- Service availability, uptime, or operational reliability of relayer infrastructure

**PRODUCTION DEPLOYMENT PREREQUISITES:**
- Third-party security audit by qualified cryptographic engineers
- Formal verification of zero-knowledge circuits
- Independent cryptographic review of protocol design
- Legal counsel review for regulatory compliance in target jurisdictions
- Operational security procedures for key management and relayer operations

## Acknowledgments

- **Tornado Cash**: Pioneering privacy protocol design
- **Zcash**: Shielded transaction architecture
- **Circom**: Zero-knowledge circuit language
- **Solana Foundation**: High-performance blockchain platform
- **Poseidon Hash**: SNARK-friendly hash function

---

**Privacy-preserving DeFi infrastructure for Solana**

Privacy is a fundamental requirement for financial sovereignty. This protocol makes it accessible on-chain through cryptographic guarantees rather than trusted intermediaries.
