```
 ____                 _     _            
|  _ \ ___  ___  ___(_) __| | ___  _ __  
| |_) / _ \/ __|/ _ \ |/ _` |/ _ \| '_ \ 
|  __/ (_) \__ \  __/ | (_| | (_) | | | |
|_|   \___/|___/\___|_|\__,_|\___/|_| |_|
                                          
Zero-Knowledge Privacy Protocol on Solana
```

# Poseidon

A production-grade zero-knowledge privacy protocol enabling fully confidential transactions on Solana using Groth16 zkSNARKs and Poseidon Merkle trees.

## The Problem

Public blockchains have a fundamental transparency problem. Every transaction on Solana is permanently visible to anyone: who sent funds, who received them, and how much was transferred. This creates significant privacy risks for users ranging from targeted attacks based on visible wealth to competitive business intelligence leaks. Traditional finance has bank secrecy laws for good reasons, but crypto users have been forced to choose between privacy and the benefits of decentralized finance.

## What Poseidon Does

Poseidon enables users to deposit SOL into a sharded privacy pool and later withdraw to any address without creating any traceable link between the deposit and withdrawal. The protocol uses zero-knowledge proofs to mathematically guarantee that withdrawals are valid without revealing anything about the transaction graph.

Observers see only that some amount entered the pool and some amount left it. They cannot determine which deposit funded which withdrawal, what the actual amounts were, or who owns which notes in the system.

## Sharded Architecture

### Why Sharding Matters

Traditional privacy protocols use a single global Merkle tree to track all note commitments. This creates a fundamental bottleneck: every deposit must update the same tree root, and every withdrawal proof must reference a recent version of that root. Under heavy load, users compete for the same state, transactions queue up waiting for confirmations, and proof generation becomes a race against tree updates.

Poseidon addresses this through a sharded Merkle tree architecture. Instead of a single monolithic tree, the protocol maintains multiple independent trees (shards), each capable of processing deposits and withdrawals in parallel.

### How It Works

Each input note in a transaction carries its own Merkle root reference. The circuit validates that the note exists in its corresponding shard without requiring all notes to share the same tree:

```
Input Note 0 --> Validates against merkleRoots[0]
Input Note 1 --> Validates against merkleRoots[1]
Input Note 2 --> Validates against merkleRoots[2]
...
```

This per-input root design enables cross-shard transactions where a user can combine notes from different shards into a single withdrawal. The circuit enforces that each note's Merkle path resolves to its declared root, maintaining cryptographic integrity across shard boundaries.

### Throughput Benefits

**Parallel Deposit Processing:** Multiple shards can accept deposits simultaneously. A system with N shards can theoretically process N times the deposit throughput of a single-tree design, as each shard maintains its own insertion index and root history.

**Reduced State Contention:** Deposits to different shards do not compete for the same on-chain state. This eliminates the serialization bottleneck where every transaction must wait for the previous one to confirm before the tree state is valid.

**Flexible Proof Generation:** Users generate proofs against their notes' specific shard roots. A deposit to Shard A does not invalidate proofs being generated for notes in Shard B. This decouples proof generation timing from global deposit activity.

**Horizontal Scaling:** As transaction volume grows, additional shards can be deployed without modifying the circuit or core protocol. Each shard operates as an independent subsystem while remaining fully interoperable through cross-shard withdrawals.

### Privacy Preservation

Sharding does not compromise the privacy model. The anonymity set for any withdrawal includes all notes across all shards that share compatible parameters. An observer cannot determine which shard a withdrawn note originated from based on the on-chain transaction, as the proof verification accepts any valid shard root.

The cross-shard join-split capability actually enhances privacy by allowing users to consolidate notes from multiple shards, further obscuring the transaction graph.

## Technical Architecture

### Zero-Knowledge Circuit Design

At the heart of Poseidon is a Groth16 zkSNARK circuit built with Circom. The circuit implements a join-split model where users can combine multiple input notes into multiple output notes while withdrawing a public amount.

The circuit enforces critical invariants:

- The sum of input balances plus any top-up equals the sum of output amounts plus the public withdrawal
- All input notes exist in the Merkle tree (proven via Merkle path verification)
- Nullifiers are correctly computed from the user's secret key and note nonces
- All amounts are within valid 64-bit ranges to prevent overflow attacks

We use the Poseidon hash function throughout because it is SNARK-friendly, requiring far fewer constraints than SHA256 or Keccak. This keeps proof generation tractable on consumer hardware.

**Circuit Parameters:**
- `nIns = 5`: Maximum input notes per transaction
- `nOuts = 6`: Maximum output notes per transaction
- `depth = 26`: Merkle tree depth (capacity: ~67 million notes)

**Public Signals (22 total):**
| Signal | Count | Description |
|--------|-------|-------------|
| merkleRoots | 5 | Per-input Merkle roots for cross-shard support |
| inputNullifier | 5 | Prevents double-spending |
| destLimbs | 4 | Recipient address (4 x u64) |
| outputCommitment | 6 | New note commitments |
| publicAmount | 1 | Amount leaving the pool |
| extAmountIn | 1 | Amount entering the pool (top-up) |

### On-Chain State Management

The program maintains a sparse Merkle tree with depth 26. Rather than storing the entire tree, we use an optimized representation that only tracks the filled subtrees along the insertion path. This reduces state size dramatically while maintaining full verification capability.

A circular buffer holds the last 100 root hashes, giving users a flexible window to generate proofs without racing against new deposits. This is critical for usability since proof generation takes time and the tree root changes with every deposit.

```rust
pub struct GlobalState {
    pub admin: Pubkey,
    pub bump: u8,
    pub escrow_bump: u8,
    pub pool_bump: u8,
    pub next_index: u32,
    pub current_root: [u8; 32],
    pub root_history_idx: u8,
    pub zeroes: Vec<u8>,           // Tree zero values
    pub filled_subtrees: Vec<u8>,  // Optimized insertion
    pub root_history: Vec<u8>,     // Last 100 roots
    pub total_deposited: u64,
    pub total_withdrawn: u64,
}
```

### Two-Phase Withdrawal Protocol

Withdrawals happen in two atomic phases to prevent MEV extraction and front-running attacks:

**Phase 1 - Prepare:**
The relayer submits the zkSNARK proof along with public signals. The program verifies the proof, creates nullifier flags for spent notes, generates change note records for any remaining balance, and locks the withdrawal parameters in a PreparedTx PDA. All recipients and amounts are cryptographically committed at this point.

**Phase 2 - Execute:**
A separate transaction transfers funds from the pool to the locked-in recipients. Because all parameters were committed during preparation, no actor can manipulate the withdrawal between verification and execution.

This separation also enables batch optimization where multiple prepared withdrawals can be executed in a single block.

### Nullifier System

Double-spending is prevented through deterministic nullifiers. When a user creates a note, they generate a random nonce. When spending that note, they compute a nullifier as:

```
nullifier = Poseidon(secret_key, nonce)
```

This nullifier is unique to that specific note and secret key combination. The program creates a permanent on-chain marker (NullifierFlag PDA) for each nullifier used, and any attempt to reuse a nullifier fails immediately.

The design ensures nullifiers reveal nothing about which note was spent. An observer sees nullifiers appear but cannot link them to specific deposits without knowing the secret key.

### Explosive Withdrawals

Standard withdrawals already break the deposit-withdrawal link, but sophisticated chain analysis might still correlate timing or amounts. Explosive withdrawals add another layer by splitting a single withdrawal across multiple intermediate wallets with randomized amounts before aggregating to the final destination.

```
zkSNARK Withdrawal --> Intermediate Wallet 1 (random %)
                   --> Intermediate Wallet 2 (random %)
                   --> ...
                   --> Intermediate Wallet N (remainder)

[Wait for confirmations]

Bundler: Intermediate Wallets --> Final Recipient
```

The split amounts are deterministically generated from the withdrawal nonce as a seed, ensuring reproducibility while appearing random to observers. A withdrawal might route through 50 or more intermediate addresses across multiple hops, creating a mixing graph that is practically impossible to unravel.

## Security Model

### Pool Accounting

Every withdrawal checks that `total_deposited >= total_withdrawn` and that the pool has sufficient lamports for the payout. These checks happen before any transfers, preventing time-of-check-time-of-use vulnerabilities.

### Proof Verification

All public inputs are validated against the BN254 scalar field before Groth16 verification. The verifying key is compiled directly into the program, eliminating any possibility of key substitution attacks.

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
| Compressed memo exploits | Strictly increasing index validation |
| Unauthorized relayer | Whitelist check in prepare_withdraw |

## Fee Structure

The relayer service operator provides critical infrastructure and receives compensation:

- **Relayer Fee**: 0.15% (15 basis points) + 0.005 SOL gas buffer
- **Maximum Fee Cap**: 5% (enforced on-chain)
- **Fee Calculation**: `relayer_fee = (withdrawal_amount * 15 / 10000) + 5_000_000 lamports`

## Recovery Mechanisms

Real-world systems need escape hatches:

**Emergency Withdraw:** If a note's root falls out of the history buffer before the user can generate a proof, the original depositor can recover funds directly. This breaks privacy but ensures funds are never permanently locked.

**Salted Nullifier Recovery:** If a withdrawal fails partway through and creates an orphaned nullifier, users can recover using a salted nullifier variant that avoids the stuck state.

**Orphaned Nullifier Cleanup:** For nullifiers created during failed prepare phases where no PreparedTx exists, the depositor can delete the orphaned marker and retry the withdrawal.

## Project Structure

```
programs/poseidon/src/
├── lib.rs              # Entry point, program definition
├── vk.rs               # Verifying key (auto-generated)
├── instructions/
│   ├── init.rs         # Initialize global state
│   ├── deposit.rs      # Deposit funds into pool
│   ├── withdraw.rs     # Two-phase withdrawal
│   ├── explosive.rs    # Split withdrawals
│   ├── fetch.rs        # Query note data
│   ├── emergency.rs    # Emergency recovery
│   ├── recover.rs      # Salted nullifier recovery
│   └── cleanup.rs      # Orphaned nullifier cleanup
└── utils/
    ├── state.rs        # Account structures
    ├── merkle.rs       # Sparse Merkle tree
    ├── verification.rs # Groth16 proof verification
    ├── crypto.rs       # BN254 field arithmetic
    ├── constants.rs    # Program constants
    └── errors.rs       # Error codes

circuits/
├── poseidon_main.circom  # Main join-split circuit
├── merkle.circom         # Merkle path verification
└── utils.circom          # Range checks, packing
```

## Getting Started

### Prerequisites

- Rust 1.70+
- Solana CLI 1.18+
- Anchor 0.32.1
- Node.js 18+
- circom 2.0.0

### Build

```bash
# Install dependencies
npm install

# Build the program
anchor build

# Generate verifying key (requires circom-chan setup)
node scripts/gen_vk_rs.js \
  --vk /path/to/privw_vk.json \
  --out programs/poseidon/src/vk.rs
```

### Deploy

```bash
anchor deploy --provider.cluster devnet
```

### Run Tests

```bash
# Full test suite with quality checks
./test_all.sh

# Tests only
./test_all.sh --tests-only

# Quick mode (skip rebuild)
./test_all.sh --quick
```

### Integration Tests

**Deposit:**
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
  --recipient <PUBKEY> \
  --wasm circuits/poseidon_main.wasm \
  --zkey circuits/privw_final.zkey
```

**Explosive Withdrawal:**
```bash
node tests/withdraw_join_split.js \
  --amount 4900000000 \
  --recipient <PUBKEY> \
  --explosive \
  --hops 5 \
  --wallets 15
```

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| TREE_DEPTH | 26 | Merkle tree depth |
| ROOT_HISTORY | 100 | Historical roots buffer |
| RELAYER_FEE_BPS | 15 | 0.15% fee |
| RELAYER_GAS_BUFFER | 5,000,000 | 0.005 SOL |
| MAX_FEE_BPS | 500 | 5% max cap |
| MAX_INS | 5 | Max input notes |
| MAX_OUTS | 6 | Max output notes |
| MAX_EXPLOSIVE_RECEIVERS | 10 | Max intermediate wallets |

## Dependencies

**Rust:**
- anchor-lang 0.32.1
- groth16-solana 0.0.3
- light-hasher 2.0.0
- bytemuck 1.14

**JavaScript:**
- @solana/web3.js ^1.95.8
- snarkjs ^0.7.5
- circomlibjs ^0.1.7
- ws ^8.18.0

## Performance

- Circuit constraints: ~150,000
- Proof generation: 10-30 seconds (WASM)
- Prepare phase CU: ~1.3 million
- Execute phase CU: ~200,000

## Roadmap

- [ ] Decentralized relayer network
- [ ] SPL token support
- [ ] Versioned transactions with ALTs
- [ ] Recursive proof aggregation
- [ ] Yield-bearing shielded positions
- [ ] Mobile SDK
- [ ] Browser extension wallet

## Disclaimer

This is experimental cryptographic software under active development. Production deployment requires third-party security audits, formal verification of circuits, and independent cryptographic review.

The authors disclaim all liability for financial losses, privacy breaches, or regulatory compliance issues arising from use of this software.

## License

MIT License

## Acknowledgments

- Tornado Cash: Pioneering privacy protocol design
- Zcash: Shielded transaction architecture
- Circom: Zero-knowledge circuit language
- Solana Foundation: High-performance blockchain platform

---

Privacy is not about hiding wrongdoing. It is about maintaining the basic financial confidentiality that traditional systems provide by default. Poseidon brings that standard to on-chain transactions.
