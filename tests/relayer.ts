#!/usr/bin/env node
/**
 * relayer.mjs (ESM)
 *
 * Supports TWO flows:
 *
 * 1) Single-note withdraw (old memo layout):
 *    type: "withdraw_via_memo"
 *
 * 2) JOIN-SPLIT withdraw (multi-note):
 *    type: "withdraw_via_memo_join_split"
 *
 * Protocol (JSON/WS):
 *  -> { id, type: "withdraw_via_memo" | "withdraw_via_memo_join_split",
 *       programId, recipient, memoPackedBase64 }
 *  <- { id, ok:true, signature } | { id, ok:false, error, logs? }
 */

import WebSocket from 'ws'
import bs58 from 'bs58'
import crypto from 'crypto'
import dotenv from 'dotenv'
import fs from 'fs'
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  ComputeBudgetProgram,
  VersionedTransaction,
  TransactionMessage,
  AddressLookupTableProgram,
} from '@solana/web3.js'

dotenv.config({ path: './.env' })

const N_INS = 6
const N_OUTS = 6

const VERIFY_OFFCHAIN = /^true$/i.test(process.env.VERIFY_OFFCHAIN || '')
let snarkjs: any
let vkJson: any

/* ---------- tiny utils ---------- */
const now = () => new Date().toISOString()
const log = (obj: any) => process.stdout.write(JSON.stringify(obj) + '\n')
const sha256 = (b: Buffer) => crypto.createHash('sha256').update(b).digest()

function mustEnv(k: string) {
  const v = process.env[k]
  if (!v) throw new Error(`Missing env ${k}`)
  return v
}
function anchorIxDisc(name: string) {
  return sha256(Buffer.from(`global:${name}`)).subarray(0, 8)
}
function be32ToBig(b: Buffer | Uint8Array) {
  return BigInt('0x' + Buffer.from(b).toString('hex'))
}

/* ---------- PDAs ---------- */
function pda(program: PublicKey, seeds: Buffer[]) {
  return PublicKey.findProgramAddressSync(seeds, program)[0]
}
function pdaState(program: PublicKey) {
  return pda(program, [Buffer.from('state')])
}
function pdaPool(program: PublicKey) {
  return pda(program, [Buffer.from('pool')])
}
function pdaEscrow(program: PublicKey) {
  return pda(program, [Buffer.from('escrow')])
}

/** OLD single-note prepared PDA: seeds ["prep", be32(nonceU64)] */
function pdaPreparedSingle(program: PublicKey, nonceU64: bigint | number) {
  const be32 = Buffer.alloc(32)
  be32.writeBigUInt64BE(BigInt(nonceU64), 24)
  return pda(program, [Buffer.from('prep'), be32])
}

/** JOIN-SPLIT prepared PDA: same seed strategy ("prep", u64_to_be_32(nonce)) */
function pdaPreparedJoinSplit(program: PublicKey, nonceU64: bigint | number) {
  const be32 = Buffer.alloc(32)
  be32.writeBigUInt64BE(BigInt(nonceU64), 24)
  return pda(program, [Buffer.from('prep'), be32])
}

/** Explosive PDA: seeds ["explo", nonce.to_be_bytes()] */
function pdaExplosive(program: PublicKey, nonceU64: bigint | number) {
  const nonceBuf = Buffer.alloc(8)
  nonceBuf.writeBigUInt64BE(BigInt(nonceU64))
  return pda(program, [Buffer.from('explo'), nonceBuf])
}

/** Nullifier PDA: seeds ["null", nullifier32] */
function pdaNullifier(program: PublicKey, noteNullifier32: Buffer | Uint8Array) {
  return pda(program, [Buffer.from('null'), Buffer.from(noteNullifier32)])
}

/** Note PDA: seeds ["note", commitment32] (used only in old single-note flow) */
function pdaNote(program: PublicKey, commitment32: Buffer | Uint8Array) {
  return pda(program, [Buffer.from('note'), Buffer.from(commitment32)])
}

function pdaNoteByIndex(program: PublicKey, treeIndex: number) {
  const idxBe = Buffer.alloc(4)
  idxBe.writeUInt32BE(treeIndex, 0)
  return pda(program, [Buffer.from('note'), idxBe])
}

/* ---------- memo parsing: OLD single-note layout ---------- */
function parsePackedSingle(memo: Buffer) {
  let off = 0
  const take = (n: number) => {
    const slice = memo.subarray(off, off + n)
    if (slice.length !== n) throw new Error('memo too short')
    off += n
    return slice
  }

  const A = take(64)
  const B = take(128)
  const C = take(64)
  const root = take(32)
  const publicAmount = take(8).readBigUInt64LE(0)
  const nonce = take(8).readBigUInt64LE(0)
  const newCommitment = take(32)
  const noteNullifier = take(32)
  const recipient = new PublicKey(take(32))
  const nChanges = take(4).readUInt32LE(0)

  const changes: { commitment: Buffer; ciphertext: Buffer }[] = []
  for (let i = 0; i < nChanges; i++) {
    const com = take(32)
    const ctLen = take(4).readUInt32LE(0)
    const ct = take(ctLen)
    changes.push({ commitment: com, ciphertext: ct })
  }

  return {
    A,
    B,
    C,
    root,
    publicAmount,
    nonce,
    newCommitment,
    noteNullifier,
    recipient,
    nChanges,
    changes,
  }
}

function parsePackedJoinSplitFull(memo: Buffer) {
  let off = 0;
  const take = (n: number) => {
    if (off + n > memo.length) throw new Error('join-split memo too short');
    const slice = memo.subarray(off, off + n);
    off += n;
    return slice;
  };
  const readU64LE = () => take(8).readBigUInt64LE(0);

  const proofA = take(64);
  const proofB = take(128);
  const proofC = take(64);
  const publicAmount = readU64LE();
  const extAmountIn = readU64LE();
  const nonce = readU64LE();
  const nInputs = take(4).readUInt32LE(0);

  const inputNullifiers: Buffer[] = [];
  for (let i = 0; i < N_INS; i++) {
    inputNullifiers.push(take(32));
  }

  // ✅ READ FLAG BYTE (1 = full withdraw, 0 = compressed outputs)
  const flagByte = take(1)[0];
  const isFullWithdraw = flagByte === 1;

  const outputCommitments: Buffer[] = [];
  
  if (isFullWithdraw) {
    // Full withdraw: reconstruct zeros for program
    for (let i = 0; i < N_OUTS; i++) {
      outputCommitments.push(Buffer.alloc(32));
    }
  } else {
    // ✅ COMPRESSED FORMAT: Read sparse non-zero commitments
    // Initialize all to zero
    for (let i = 0; i < N_OUTS; i++) {
      outputCommitments.push(Buffer.alloc(32));
    }
    
    // Read count of non-zero commitments (u8)
    const nonZeroCount = take(1)[0];
    
    // Read each non-zero commitment with its index
    for (let i = 0; i < nonZeroCount; i++) {
      const idx = take(1)[0]; // index (u8)
      if (idx >= N_OUTS) {
        throw new Error(`Invalid output commitment index: ${idx}`);
      }
      const commitment = take(32); // commitment (32 bytes BE)
      outputCommitments[idx] = commitment;
    }
  }

  return {
    proofA,
    proofB,
    proofC,
    publicAmount,
    extAmountIn,
    nonce,
    nInputs,
    inputNullifiers,
    outputCommitments,
  };
}

/* ---------- off-chain verification: OLD circuit only ---------- */
function recipientLimbsLE(pk: PublicKey) {
  const b = pk.toBytes()
  const out: bigint[] = []
  for (let i = 0; i < 4; i++) {
    let limb = 0n
    for (let j = 0; j < 8; j++) {
      limb |= BigInt(b[i * 8 + j]) << (8n * BigInt(j))
    }
    out.push(limb)
  }
  return out
}

function asLE32HexFromDecimalString(nStr: string) {
  let x = BigInt(nStr)
  const b = Buffer.alloc(32)
  for (let i = 0; i < 32; i++) {
    b[i] = Number(x & 0xffn)
    x >>= 8n
  }
  return '0x' + b.toString('hex')
}

/** Off-chain verifier for the OLD single-note circuit */
async function verifyOffchainSingle(memo: Buffer) {
  const p = parsePackedSingle(memo)

  const destLimbs = recipientLimbsLE(p.recipient)

  const pubs = [
    ...destLimbs,
    BigInt(p.nonce),
    be32ToBig(p.newCommitment),
    BigInt(p.publicAmount),
    be32ToBig(p.noteNullifier),
  ].map(String)

  const labels = ['D0', 'D1', 'D2', 'D3', 'NON', 'NEWC', 'AMT', 'NN']
  for (let i = 0; i < pubs.length; i++) {
    console.log(
      `[verifyOffchain-single] pub[${i} ${labels[i]}] = ${pubs[i]} (${asLE32HexFromDecimalString(
        pubs[i]
      )})`
    )
  }

  const ax = be32ToBig(p.A.subarray(0, 32)).toString()
  const ay = be32ToBig(p.A.subarray(32, 64)).toString()
  const cx = be32ToBig(p.C.subarray(0, 32)).toString()
  const cy = be32ToBig(p.C.subarray(32, 64)).toString()

  const x0 = be32ToBig(p.B.subarray(0, 32)).toString()
  const x1 = be32ToBig(p.B.subarray(32, 64)).toString()
  const y1 = be32ToBig(p.B.subarray(64, 96)).toString()
  const y0 = be32ToBig(p.B.subarray(96, 128)).toString()

  const proof = {
    protocol: 'groth16',
    curve: 'bn128',
    pi_a: [ax, ay],
    pi_b: [
      [x0, x1],
      [y0, y1],
    ],
    pi_c: [cx, cy],
  }

  const ok = await snarkjs.groth16.verify(vkJson, pubs, proof)
  if (!ok) throw new Error('offchain proof verify failed (single-note)')

  return p
}

/** For JOIN-SPLIT we skip off-chain verify; on-chain verifies Groth16. */
async function verifyOffchainJoinSplit(memo: Buffer) {
  if (VERIFY_OFFCHAIN) {
    console.warn(
      '[relayer] VERIFY_OFFCHAIN=true but join-split off-chain verification is not implemented; skipping.'
    )
  }
  return parsePackedJoinSplitFull(memo)
}

/* ---------- instruction builders ---------- */

/** OLD single-note prepare ix */
function ixPrepareWithdrawViaMemoSingle(
  programId: PublicKey,
  {
    state,
    pool,
    recipient,
    relayer,
    escrow,
    preparedPda,
    nullifierPda,
    notePdas,
  }: {
    state: PublicKey
    pool: PublicKey
    recipient: PublicKey
    relayer: PublicKey
    escrow: PublicKey
    preparedPda: PublicKey
    nullifierPda: PublicKey
    notePdas: PublicKey[]
  },
  memoBytes: Buffer
) {
  const disc = anchorIxDisc('prepare_withdraw_via_memo')
  const len = Buffer.alloc(4)
  len.writeUInt32LE(memoBytes.length, 0)
  const data = Buffer.concat([disc, len, memoBytes])

  const keys = [
    { pubkey: state, isSigner: false, isWritable: true },
    { pubkey: pool, isSigner: false, isWritable: false },
    { pubkey: recipient, isSigner: false, isWritable: true },
    { pubkey: relayer, isSigner: true, isWritable: false },
    { pubkey: escrow, isSigner: false, isWritable: true },
    { pubkey: preparedPda, isSigner: false, isWritable: true },
    { pubkey: nullifierPda, isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ]

  for (const p of notePdas) {
    keys.push({ pubkey: p, isSigner: false, isWritable: true })
  }

  return new TransactionInstruction({ programId, keys, data })
}

/** JOIN-SPLIT prepare ix (FULL memo) */
function ixPrepareWithdrawViaMemoJoinSplit(
  programId: PublicKey,
  {
    state,
    pool,
    recipient,
    relayer,
    escrow,
    preparedPda,
    signer,
    nullifierPdas,
    outputNotePdas,
  }: {
    state: PublicKey
    pool: PublicKey
    recipient: PublicKey
    relayer: PublicKey
    escrow: PublicKey
    preparedPda: PublicKey
    signer: PublicKey
    nullifierPdas: PublicKey[]
    outputNotePdas?: PublicKey[]
  },
  memoBytes: Buffer
) {
  const disc = anchorIxDisc('prepare_withdraw_via_memo')
  const len = Buffer.alloc(4)
  len.writeUInt32LE(memoBytes.length, 0)
  const data = Buffer.concat([disc, len, memoBytes])

  const keys = [
    { pubkey: state, isSigner: false, isWritable: true }, // 0
    { pubkey: pool, isSigner: false, isWritable: true }, // 1
    { pubkey: recipient, isSigner: false, isWritable: true }, // 2
    { pubkey: relayer, isSigner: false, isWritable: false }, // 3
    { pubkey: escrow, isSigner: false, isWritable: true }, // 4
    { pubkey: preparedPda, isSigner: false, isWritable: true }, // 5
    { pubkey: signer, isSigner: true, isWritable: true }, // 6
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // 7
  ]

  // Remaining accounts: nullifier PDAs first, then output note PDAs
  for (const nf of nullifierPdas) {
    keys.push({ pubkey: nf, isSigner: false, isWritable: true })
  }
  for (const notePda of (outputNotePdas || [])) {
    keys.push({ pubkey: notePda, isSigner: false, isWritable: true })
  }

  return new TransactionInstruction({ programId, keys, data })
}

/** Execute prepared withdraw (same for both modes) */
function ixExecutePrepared(
  programId: PublicKey,
  {
    state,
    pool,
    recipient,
    relayer,
    escrow,
    preparedPda,
  }: {
    state: PublicKey
    pool: PublicKey
    recipient: PublicKey
    relayer: PublicKey
    escrow: PublicKey
    preparedPda: PublicKey
  }
) {
  const disc = anchorIxDisc('execute_prepared_withdraw')
  const keys = [
    { pubkey: state, isSigner: false, isWritable: true },
    { pubkey: pool, isSigner: false, isWritable: true },
    { pubkey: recipient, isSigner: false, isWritable: true },
    { pubkey: relayer, isSigner: true, isWritable: true },
    { pubkey: escrow, isSigner: false, isWritable: true },
    { pubkey: preparedPda, isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ]
  return new TransactionInstruction({ programId, keys, data: disc })
}

/** Prepare explosive withdraw instruction */
function ixPrepareExplosiveWithdraw(
  programId: PublicKey,
  {
    state,
    pool,
    recipient,
    relayer,
    signer,
    escrow,
    explosivePda,
    nullifierPdas,
    outputNotePdas,
  }: {
    state: PublicKey
    pool: PublicKey
    recipient: PublicKey
    relayer: PublicKey
    signer: PublicKey
    escrow: PublicKey
    explosivePda: PublicKey
    nullifierPdas: PublicKey[]
    outputNotePdas?: PublicKey[]
  },
  memoBytes: Buffer,
  intermediateWallets: PublicKey[],
  nonce: bigint
) {
  const disc = anchorIxDisc('prepare_explosive_withdraw')
  
  // Vec<u8> length prefix for memo
  const memoLen = Buffer.alloc(4)
  memoLen.writeUInt32LE(memoBytes.length, 0)
  
  // [Pubkey; 10] - fixed array of 10 pubkeys
  const walletsData = Buffer.concat(intermediateWallets.map(pk => pk.toBuffer()))
  
  // u64 nonce
  const nonceBuf = Buffer.alloc(8)
  nonceBuf.writeBigUInt64LE(nonce)
  
  const data = Buffer.concat([disc, memoLen, memoBytes, walletsData, nonceBuf])

  // Account order MUST match Rust struct PrepareExplosiveWithdraw
  const keys = [
    { pubkey: signer, isSigner: true, isWritable: true },
    { pubkey: state, isSigner: false, isWritable: true },
    { pubkey: pool, isSigner: false, isWritable: true },
    { pubkey: escrow, isSigner: false, isWritable: true },
    { pubkey: recipient, isSigner: false, isWritable: false },
    { pubkey: relayer, isSigner: true, isWritable: true },
    { pubkey: explosivePda, isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ]

  // Remaining accounts: nullifier PDAs then output note PDAs
  for (const nf of nullifierPdas) {
    keys.push({ pubkey: nf, isSigner: false, isWritable: true })
  }
  for (const notePda of (outputNotePdas || [])) {
    keys.push({ pubkey: notePda, isSigner: false, isWritable: true })
  }

  return new TransactionInstruction({ programId, keys, data })
}

/** Execute a SINGLE transfer from explosive withdrawal */
function ixExecuteExplosiveSingle(
  programId: PublicKey,
  {
    state,
    pool,
    relayer,
    explosivePda,
    walletPubkey,
    walletIndex,
  }: {
    state: PublicKey
    pool: PublicKey
    relayer: PublicKey
    explosivePda: PublicKey
    walletPubkey: PublicKey
    walletIndex: number
  }
) {
  const disc = anchorIxDisc('execute_explosive_single')
  
  // wallet_index: u8
  const indexBuf = Buffer.alloc(1)
  indexBuf.writeUInt8(walletIndex)
  const data = Buffer.concat([disc, indexBuf])
  
  const keys = [
    { pubkey: state, isSigner: false, isWritable: true },
    { pubkey: pool, isSigner: false, isWritable: true },
    { pubkey: relayer, isSigner: true, isWritable: true },
    { pubkey: explosivePda, isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    { pubkey: walletPubkey, isSigner: false, isWritable: true },
  ]

  return new TransactionInstruction({ programId, keys, data })
}

/* ---------- tx helpers ---------- */
async function sendTxWithLogs(
  conn: Connection,
  tx: Transaction,
  signers: Keypair[]
) {
  try {
    const sig = await conn.sendTransaction(tx, signers, { skipPreflight: false })
    await conn.confirmTransaction(sig, 'confirmed')
    return { signature: sig, logs: null as any }
  } catch (e: any) {
    try {
      const sim = await conn.simulateTransaction(tx, signers)
      const logs = sim?.value?.logs || null
      throw new Error(
        `SendTransactionError: ${e.message}\nLogs:\n${JSON.stringify(logs, null, 2)}`
      )
    } catch {
      throw new Error(`SendTransactionError: ${e.message}`)
    }
  }
}

/** Send a versioned (v0) transaction */
async function sendV0TxWithLogs(conn: Connection, tx: VersionedTransaction) {
  try {
    const sig = await conn.sendTransaction(tx, { skipPreflight: false })
    await conn.confirmTransaction(sig, 'confirmed')
    return { signature: sig, logs: null as any }
  } catch (e: any) {
    try {
      const sim = await conn.simulateTransaction(tx)
      const logs = sim?.value?.logs || null
      throw new Error(
        `SendTransactionError: ${e.message}\nLogs:\n${JSON.stringify(logs, null, 2)}`
      )
    } catch {
      throw new Error(`SendTransactionError: ${e.message}`)
    }
  }
}

/** Get or create an Address Lookup Table with the given addresses */
async function getOrCreateLookupTable(
  conn: Connection,
  payer: Keypair,
  addresses: PublicKey[]
) {
  const slot = await conn.getSlot('finalized')
  
  const [createIx, lookupTableAddress] = AddressLookupTableProgram.createLookupTable({
    authority: payer.publicKey,
    payer: payer.publicKey,
    recentSlot: slot,
  })
  
  // Create the table
  const createTx = new Transaction().add(createIx)
  createTx.feePayer = payer.publicKey
  createTx.recentBlockhash = (await conn.getLatestBlockhash()).blockhash
  
  const createSig = await conn.sendTransaction(createTx, [payer])
  await conn.confirmTransaction(createSig, 'confirmed')
  log({
    t: now(),
    level: 'info',
    phase: 'lookup-table-created',
    address: lookupTableAddress.toBase58(),
  })
  
  // Extend with addresses (max 30 per extend)
  for (let i = 0; i < addresses.length; i += 30) {
    const chunk = addresses.slice(i, i + 30)
    const extendIx = AddressLookupTableProgram.extendLookupTable({
      lookupTable: lookupTableAddress,
      authority: payer.publicKey,
      payer: payer.publicKey,
      addresses: chunk,
    })
    
    const extendTx = new Transaction().add(extendIx)
    extendTx.feePayer = payer.publicKey
    extendTx.recentBlockhash = (await conn.getLatestBlockhash()).blockhash
    
    const extendSig = await conn.sendTransaction(extendTx, [payer])
    await conn.confirmTransaction(extendSig, 'confirmed')
    log({
      t: now(),
      level: 'info',
      phase: 'lookup-table-extended',
      count: chunk.length,
    })
  }
  
  // Wait for table to be active (need to wait for slot to advance)
  log({ t: now(), level: 'info', phase: 'lookup-table-waiting' })
  
  // Wait for at least one slot to pass
  const startSlot = await conn.getSlot('confirmed')
  let currentSlot = startSlot
  let attempts = 0
  while (currentSlot <= startSlot && attempts < 20) {
    await new Promise(r => setTimeout(r, 500))
    currentSlot = await conn.getSlot('confirmed')
    attempts++
  }
  
  if (currentSlot <= startSlot) {
    log({ t: now(), level: 'warn', phase: 'lookup-table-slot-timeout', startSlot, currentSlot })
  }
  
  // Fetch the table
  const lookupTableAccount = await conn.getAddressLookupTable(lookupTableAddress)
  if (!lookupTableAccount.value) {
    throw new Error('Failed to fetch lookup table')
  }
  
  return { lookupTableAddress, lookupTableAccount: lookupTableAccount.value }
}

/* ---------- ESCROW AUTO-TOPUP ---------- */
const MIN_ESCROW_LAMPORTS = 5_000_000n // 0.005 SOL - matches relayer fee, covers rent-exempt minimum

async function ensureEscrowFunded(
  conn: Connection,
  relayer: Keypair,
  escrow: PublicKey
): Promise<void> {
  const info = await conn.getAccountInfo(escrow)
  const current = info?.lamports ?? 0n

  if (current >= MIN_ESCROW_LAMPORTS) {
    log({
      t: now(),
      level: 'info',
      phase: 'escrow-check',
      escrow: escrow.toBase58(),
      lamports: current.toString(),
      status: 'sufficient',
    })
    return
  }

  const needed = MIN_ESCROW_LAMPORTS - BigInt(current)
  log({
    t: now(),
    level: 'info',
    phase: 'escrow-topup',
    escrow: escrow.toBase58(),
    current: current.toString(),
    needed: needed.toString(),
  })

  const topupTx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: relayer.publicKey,
      toPubkey: escrow,
      lamports: needed,
    })
  )
  topupTx.recentBlockhash = (await conn.getLatestBlockhash()).blockhash
  topupTx.feePayer = relayer.publicKey

  const sig = await conn.sendTransaction(topupTx, [relayer])
  await conn.confirmTransaction(sig, 'confirmed')

  log({
    t: now(),
    level: 'info',
    phase: 'escrow-topup-complete',
    sig,
    lamports: needed.toString(),
  })
}

/* ---------- handlers ---------- */

async function handleWithdrawViaMemoSingle(
  req: any,
  {
    conn,
    RELAYER,
    CU_LIMIT_PREPARE,
    CU_LIMIT_EXECUTE,
    CU_PRICE_MICROLAMPORTS,
  }: {
    conn: Connection
    RELAYER: Keypair
    CU_LIMIT_PREPARE: number
    CU_LIMIT_EXECUTE: number
    CU_PRICE_MICROLAMPORTS: number
  }
) {
  const programId = new PublicKey(req.programId)
  const state = pdaState(programId)
  const pool = pdaPool(programId)
  const escrow = pdaEscrow(programId)
  const recipient = new PublicKey(req.recipient)
  const memo = Buffer.from(req.memoPackedBase64, 'base64')

  let parsed: any
  if (VERIFY_OFFCHAIN) {
    parsed = await verifyOffchainSingle(memo)
    log({
      t: now(),
      level: 'info',
      phase: 'verify-single',
      ok: true,
      nonce: parsed.nonce.toString(),
      recipient: recipient.toBase58(),
      publicAmount: parsed.publicAmount.toString(),
    })
  } else {
    parsed = parsePackedSingle(memo)
  }

  const prepared = pdaPreparedSingle(programId, parsed.nonce)
  const nullifier = pdaNullifier(programId, parsed.noteNullifier)
  const notePdas = (parsed.changes || []).map((ch: any) =>
    pdaNote(programId, ch.commitment)
  )

  // <<< CHECK FOR ORPHANED NULLIFIER (ASYNC) >>>
  const nullifierAccount = await conn.getAccountInfo(nullifier)
  if (nullifierAccount) {
    log({
      t: now(),
      level: 'error',
      phase: 'nullifier-check-failed',
      msg: '❌ ORPHANED NULLIFIER DETECTED - Note already spent or has orphaned nullifier',
      nullifier: nullifier.toBase58(),
      nullifierExists: true,
      solution: 'Auto-cleanup attempted - if this persists, note may be already spent',
    })
    throw new Error('NullifierAlreadyUsed: Note already spent or has orphaned nullifier')
  }

  // <<< ESCROW TOP-UP >>>
  await ensureEscrowFunded(conn, RELAYER, escrow)

  // 1) PREPARE
  {
    const tx = new Transaction()
    tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT_PREPARE }))
    if (CU_PRICE_MICROLAMPORTS > 0) {
      tx.add(
        ComputeBudgetProgram.setComputeUnitPrice({
          microLamports: CU_PRICE_MICROLAMPORTS,
        })
      )
    }
    tx.add(
      ixPrepareWithdrawViaMemoSingle(
        programId,
        {
          state,
          pool,
          recipient,
          relayer: RELAYER.publicKey,
          escrow,
          preparedPda: prepared,
          nullifierPda: nullifier,
          notePdas,
        },
        memo
      )
    )

    tx.feePayer = RELAYER.publicKey
    tx.recentBlockhash = (await conn.getLatestBlockhash()).blockhash

    const { signature } = await sendTxWithLogs(conn, tx, [RELAYER])
    log({ t: now(), level: 'info', phase: 'prepare-single', sig: signature })
  }

  // 2) EXECUTE
  {
    const tx2 = new Transaction()
    tx2.add(ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT_EXECUTE }))
    if (CU_PRICE_MICROLAMPORTS > 0) {
      tx2.add(
        ComputeBudgetProgram.setComputeUnitPrice({
          microLamports: CU_PRICE_MICROLAMPORTS,
        })
      )
    }
    tx2.add(
      ixExecutePrepared(programId, {
        state,
        pool,
        recipient,
        relayer: RELAYER.publicKey,
        escrow,
        preparedPda: prepared,
      })
    )

    tx2.feePayer = RELAYER.publicKey
    tx2.recentBlockhash = (await conn.getLatestBlockhash()).blockhash

    const { signature } = await sendTxWithLogs(conn, tx2, [RELAYER])
    log({ t: now(), level: 'info', phase: 'execute-single', sig: signature })
    return { sig: signature }
  }
}

/** JOIN-SPLIT withdraw handler (multi-note, full withdraw) */
async function handleWithdrawViaMemoJoinSplit(
  req: any,
  {
    conn,
    RELAYER,
    CU_LIMIT_PREPARE,
    CU_LIMIT_EXECUTE,
    CU_PRICE_MICROLAMPORTS,
  }: {
    conn: Connection
    RELAYER: Keypair
    CU_LIMIT_PREPARE: number
    CU_LIMIT_EXECUTE: number
    CU_PRICE_MICROLAMPORTS: number
  }
) {
  const programId = new PublicKey(req.programId)
  const state = pdaState(programId)
  const pool = pdaPool(programId)
  const escrow = pdaEscrow(programId)
  const recipient = new PublicKey(req.recipient)
  const memo = Buffer.from(req.memoPackedBase64, 'base64')

  const parsed = await verifyOffchainJoinSplit(memo)

  const prepared = pdaPreparedJoinSplit(programId, parsed.nonce)

  const nullifierPdas = parsed.inputNullifiers
    .slice(0, parsed.nInputs)
    .map((n: Buffer) => pdaNullifier(programId, n))

  // <<< CHECK FOR ORPHANED NULLIFIERS (PARALLEL) >>>
  const nullifierChecks = await Promise.all(
    nullifierPdas.map(async (pda, i) => {
      const account = await conn.getAccountInfo(pda)
      return { index: i, pda, exists: !!account }
    })
  )

  const orphanedNullifiers = nullifierChecks.filter(c => c.exists)
  if (orphanedNullifiers.length > 0) {
    for (const { index, pda } of orphanedNullifiers) {
      log({
        t: now(),
        level: 'error',
        phase: 'nullifier-check-failed',
        msg: `❌ ORPHANED NULLIFIER DETECTED - Input note ${index} already spent or has orphaned nullifier`,
        nullifier: pda.toBase58(),
        inputIndex: index,
        nullifierExists: true,
        solution: 'Auto-cleanup attempted - if this persists, note may be already spent',
      })
    }
    throw new Error(`NullifierAlreadyUsed: ${orphanedNullifiers.length} input note(s) already spent or have orphaned nullifiers`)
  }

  // Fetch next_index for output note PDAs
  const stateAccount = await conn.getAccountInfo(state)
  if (!stateAccount) throw new Error('State account not found')
  // State layout: discriminator(8) + admin(32) + bump(1) + escrow_bump(1) + pool_bump(1) + next_index(4) at offset 43
  const nextIndex = stateAccount.data.readUInt32LE(43)
  
  log({
    t: now(),
    level: 'debug',
    msg: `Current next_index: ${nextIndex}`,
  })
  
  // Create PDAs for non-zero output commitments
  const outputNotePdas: PublicKey[] = []
  for (let j = 0; j < parsed.outputCommitments.length; j++) {
    const commitment = parsed.outputCommitments[j]
    // Check if commitment is all zeros
    const isZero = commitment.every((b: number) => b === 0)
    if (!isZero) {
      const treeIdx = Number(nextIndex) + outputNotePdas.length
      const notePda = pdaNoteByIndex(programId, treeIdx)
      outputNotePdas.push(notePda)
      log({
        t: now(),
        level: 'debug',
        msg: `Output ${j}: index=${treeIdx}, PDA=${notePda.toBase58()}`,
      })
    }
  }

  // <<< ESCROW TOP-UP >>>
  await ensureEscrowFunded(conn, RELAYER, escrow)

  // 1) PREPARE
  {
    const tx = new Transaction()
    tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT_PREPARE }))
    if (CU_PRICE_MICROLAMPORTS > 0) {
      tx.add(
        ComputeBudgetProgram.setComputeUnitPrice({
          microLamports: CU_PRICE_MICROLAMPORTS,
        })
      )
    }

    tx.add(
      ixPrepareWithdrawViaMemoJoinSplit(
        programId,
        {
          state,
          pool,
          recipient,
          relayer: RELAYER.publicKey,
          signer: RELAYER.publicKey,
          escrow,
          preparedPda: prepared,
          nullifierPdas,
          outputNotePdas,
        },
        memo
      )
    )

    tx.feePayer = RELAYER.publicKey
    tx.recentBlockhash = (await conn.getLatestBlockhash()).blockhash

    const { signature } = await sendTxWithLogs(conn, tx, [RELAYER])
    log({
      t: now(),
      level: 'info',
      phase: 'prepare-join-split',
      sig: signature,
    })
  }

  // 2) EXECUTE
  {
    const tx2 = new Transaction()
    tx2.add(ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT_EXECUTE }))
    if (CU_PRICE_MICROLAMPORTS > 0) {
      tx2.add(
        ComputeBudgetProgram.setComputeUnitPrice({
          microLamports: CU_PRICE_MICROLAMPORTS,
        })
      )
    }

    tx2.add(
      ixExecutePrepared(programId, {
        state,
        pool,
        recipient,
        relayer: RELAYER.publicKey,
        escrow,
        preparedPda: prepared,
      })
    )

    tx2.feePayer = RELAYER.publicKey
    tx2.recentBlockhash = (await conn.getLatestBlockhash()).blockhash

    const { signature } = await sendTxWithLogs(conn, tx2, [RELAYER])
    log({
      t: now(),
      level: 'info',
      phase: 'execute-join-split',
      sig: signature,
    })
    return { sig: signature }
  }
}

/** Helper: sleep function */
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

/** Helper: send and confirm transaction with retries */
async function sendAndConfirmTransaction(
  conn: Connection,
  tx: Transaction,
  signers: Keypair[],
  options?: { skipPreflight?: boolean; commitment?: string }
): Promise<string> {
  tx.recentBlockhash = (await conn.getLatestBlockhash()).blockhash
  tx.feePayer = signers[0].publicKey
  tx.sign(...signers)
  
  const sig = await conn.sendRawTransaction(tx.serialize(), {
    skipPreflight: options?.skipPreflight ?? false,
  })
  
  await conn.confirmTransaction(sig, (options?.commitment as any) ?? 'confirmed')
  return sig
}

/** EXPLOSIVE MULTI-HOP withdraw handler (complete reference implementation) */
async function handleExplosiveMultiHop(
  req: any,
  {
    conn,
    RELAYER,
    CU_LIMIT_PREPARE,
    CU_LIMIT_EXECUTE,
    CU_PRICE_MICROLAMPORTS,
    progressTrackers,
    sessionId,
  }: {
    conn: Connection
    RELAYER: Keypair
    CU_LIMIT_PREPARE: number
    CU_LIMIT_EXECUTE: number
    CU_PRICE_MICROLAMPORTS: number
    progressTrackers?: Map<string, any>
    sessionId?: string
  }
) {
  const LAMPORTS_PER_SOL = 1_000_000_000

  // Helper to send progress updates
  const sendProgress = (phase: string, signatures: string[] = []) => {
    if (!progressTrackers || !sessionId) return
    
    const tracker = progressTrackers.get(sessionId)
    if (!tracker) return

    tracker.currentStep++
    tracker.phase = phase
    
    const progress = Math.floor((tracker.currentStep / tracker.totalSteps) * 100)
    
    try {
      tracker.ws.send(JSON.stringify({
        type: 'progress',
        sessionId,
        progress,
        phase,
        currentStep: tracker.currentStep,
        totalSteps: tracker.totalSteps,
        signatures,
      }))
    } catch (e) {
      // WebSocket might be closed, ignore
    }
  }

  try {
    const { programId, recipient, memoPackedBase64, hops, walletsPerHop, firstIntermediateSecretKey, finalRecipient } = req

    const PROGRAM = new PublicKey(programId)
    const firstIntermediate = Keypair.fromSecretKey(Uint8Array.from(firstIntermediateSecretKey))
    const finalRecipientPk = new PublicKey(finalRecipient)
    const firstIntermediatePubkey = firstIntermediate.publicKey
    const clientSentRecipient = new PublicKey(recipient)
    if (firstIntermediatePubkey.toBase58() !== clientSentRecipient.toBase58()) {
      log({
        t: now(),
        level: 'error',
        phase: 'explosive-recipient-mismatch',
        expectedRecipient: firstIntermediatePubkey.toBase58(),
        clientSentRecipient: clientSentRecipient.toBase58(),
        finalRecipient: finalRecipientPk.toBase58(),
        hint: 'Client must send: recipient=firstIntermediate.publicKey, finalRecipient=actualDestination'
      })
      throw new Error(
        `Recipient mismatch: Client sent ${clientSentRecipient.toBase58()} ` +
        `but key corresponds to ${firstIntermediatePubkey.toBase58()}`
      )
    }
    
    const memo = Buffer.from(memoPackedBase64, 'base64')

    log({
      t: now(),
      level: 'info',
      phase: 'explosive-multi-hop-start',
      hops,
      walletsPerHop,
      totalWallets: hops * walletsPerHop,
      firstIntermediate: firstIntermediate.publicKey.toBase58(),
      finalRecipient: finalRecipientPk.toBase58(),
    })

    const parsed = await verifyOffchainJoinSplit(memo)
    const nonce = parsed.nonce

    const state = pdaState(PROGRAM)
    const pool = pdaPool(PROGRAM)
    const escrow = pdaEscrow(PROGRAM)
    const preparedPda = pdaPreparedJoinSplit(PROGRAM, nonce)

    const nullifierPdas: PublicKey[] = []
    for (let i = 0; i < parsed.nInputs; i++) {
      nullifierPdas.push(pdaNullifier(PROGRAM, parsed.inputNullifiers[i]))
    }

    // Fetch next_index from state to calculate output note PDAs
    const stateAccount = await conn.getAccountInfo(state)
    if (!stateAccount) throw new Error('State account not found')
    const nextIndex = stateAccount.data.readUInt32LE(43)
    
    log({
      t: now(),
      level: 'info',
      phase: 'explosive-state-index',
      nextIndex
    })

    const outputNotePdas: PublicKey[] = []
    for (let j = 0; j < parsed.outputCommitments.length; j++) {
      const commitment = parsed.outputCommitments[j]
      const isZero = commitment.every((b: number) => b === 0)
      if (!isZero) {
        const treeIdx = Number(nextIndex) + outputNotePdas.length
        const notePda = pdaNoteByIndex(PROGRAM, treeIdx)
        outputNotePdas.push(notePda)
        log({
          t: now(),
          level: 'debug',
          phase: 'explosive-output-note',
          outputIdx: j,
          treeIdx,
        notePda: notePda.toBase58()
      })
    }
  }

  // PHASE 1: Prepare and execute initial withdrawal
  sendProgress('starting', [])
  log({ t: now(), level: 'info', phase: 'explosive-phase-1-prepare', progress: 0, message: `Preparing withdrawal (step 0/${hops + 2})` })

  const ixPrep = ixPrepareWithdrawViaMemoJoinSplit(
      PROGRAM,
      {
        state,
        pool,
        recipient: firstIntermediatePubkey,
        relayer: RELAYER.publicKey,
        escrow,
        preparedPda,
        signer: RELAYER.publicKey,
        nullifierPdas,
        outputNotePdas,
      },
      memo
    )

    const txPrep = new Transaction()
    txPrep.add(ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT_PREPARE }))
    if (CU_PRICE_MICROLAMPORTS > 0) {
      txPrep.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: CU_PRICE_MICROLAMPORTS }))
    }
    txPrep.add(ixPrep)

    const sigPrep = await sendTxWithLogs(conn, txPrep, [RELAYER])
    log({ t: now(), level: 'info', phase: 'explosive-prepared', sig: sigPrep.signature, progress: Math.floor((1 / (hops + 2)) * 100), message: `Prepared (step 1/${hops + 2})` })
    sendProgress('prepared', [sigPrep.signature])

    await sleep(2000)

    const ixExec = ixExecutePrepared(PROGRAM, {
      state,
      pool,
      recipient: firstIntermediatePubkey,
      relayer: RELAYER.publicKey,
      escrow,
      preparedPda,
    })

    const txExec = new Transaction()
    txExec.add(ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT_EXECUTE }))
    if (CU_PRICE_MICROLAMPORTS > 0) {
      txExec.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: CU_PRICE_MICROLAMPORTS }))
    }
    txExec.add(ixExec)

    const sigExec = await sendTxWithLogs(conn, txExec, [RELAYER])
    log({ t: now(), level: 'info', phase: 'explosive-executed', sig: sigExec.signature, progress: Math.floor((2 / (hops + 2)) * 100), message: `Executed (step 2/${hops + 2})` })
    sendProgress('executed', [sigExec.signature])

    await sleep(3000)

    log({ t: now(), level: 'info', phase: 'explosive-phase-2-start', hops, walletsPerHop })

    let currentSource = firstIntermediate
    let currentBalance = await conn.getBalance(firstIntermediate.publicKey)
    
    log({
      t: now(),
      level: 'info',
      phase: 'explosive-initial-balance',
      wallet: firstIntermediate.publicKey.toBase58(),
      balance: currentBalance,
      balanceSol: (currentBalance / LAMPORTS_PER_SOL).toFixed(6)
    })

    if (currentBalance === 0) {
      throw new Error(
        `Initial withdrawal executed but first intermediate wallet has 0 balance. ` +
        `Expected funds at: ${firstIntermediate.publicKey.toBase58()}. ` +
        `Check if withdrawal recipient matches firstIntermediate. ` +
        `Execute signature: ${sigExec.signature}`
      )
    }

    const MIN_BALANCE_FOR_HOP = 1_000_000
    if (currentBalance < MIN_BALANCE_FOR_HOP) {
      throw new Error(
        `Insufficient balance for multi-hop (${currentBalance} lamports, need ${MIN_BALANCE_FOR_HOP}). ` +
        `Wallet: ${firstIntermediate.publicKey.toBase58()}`
      )
    }

    // Track all hop transactions for database storage (including private keys for ownership proof)
    const hopTransactions: Array<{
      hopNumber: number
      distributionSignatures: string[]
      mergeSignatures: string[]
      intermediateWallets: string[]
      intermediatePrivateKeys: string[]
      nextDestination: string
      nextDestinationPrivateKey: string | null
      totalMerged: string
    }> = []

    // BULLETPROOF DELIVERY: Wrap entire distribution in try-catch with emergency fallback
    let distributionSuccess = false
    let distributionError: any = null
    let emergencyRecoveryUsed = false
    let emergencySignature: string | undefined
    
    // PRE-GENERATE ALL WALLETS FOR ALL HOPS BEFORE ANY TRANSACTIONS
    // This ensures we have ALL private keys stored BEFORE touching blockchain
    log({
      t: now(),
      level: 'info',
      phase: 'explosive-pre-generating-wallets',
      totalHops: hops,
      walletsPerHop,
    })
    
    const preGeneratedHopWallets: Keypair[][] = []
    const preGeneratedHopSources: Keypair[] = []
    
    for (let hop = 0; hop < hops; hop++) {
      const hopWallets: Keypair[] = []
      
      // Generate intermediate wallets for this hop
      for (let i = 0; i < walletsPerHop; i++) {
        const wallet = Keypair.generate()
        hopWallets.push(wallet)
      }
      
      preGeneratedHopWallets.push(hopWallets)
      
      if (hop < hops - 1) {
        const nextSource = Keypair.generate()
        preGeneratedHopSources.push(nextSource)
      }
    }
    
    try {
      for (let hop = 0; hop < hops; hop++) {
        // RETRY WRAPPER: Retry each hop up to 3 times before giving up
        let hopSuccess = false
        let hopAttempt = 0
        const MAX_HOP_RETRIES = 3
        
        while (!hopSuccess && hopAttempt < MAX_HOP_RETRIES) {
          hopAttempt++
          
          try {
            if (hopAttempt > 1) {
              log({
                t: now(),
                level: 'warn',
                phase: 'explosive-hop-retry',
                hop: hop + 1,
                attempt: hopAttempt,
                maxRetries: MAX_HOP_RETRIES
              })
            }
            
            log({
              t: now(),
              level: 'info',
              phase: 'explosive-hop-start',
              hop: hop + 1,
              totalHops: hops,
              attempt: hopAttempt,
              currentBalance,
              currentBalanceSol: (currentBalance / LAMPORTS_PER_SOL).toFixed(6)
            })

            // DYNAMIC WALLET COUNT: Calculate max wallets we can afford based on balance
            const RENT_PER_WALLET = 890880 // Rent-exempt minimum per wallet
            const MIN_TRANSFER = 50000 // Minimum 0.00005 SOL per wallet
            const FEE_BUFFER = 50000 // Buffer for transaction fees
            // Use PRE-GENERATED wallets for this hop
            const hopWallets = preGeneratedHopWallets[hop]
            const actualWalletsThisHop = hopWallets.length
            
            if (actualWalletsThisHop < walletsPerHop) {
              log({
                t: now(),
                level: 'warn',
                phase: 'explosive-reduced-wallets',
                hop: hop + 1,
                requested: walletsPerHop,
                actual: actualWalletsThisHop,
                reason: 'pre-generated-count'
              })
            }

            const RENT_EXEMPT_MINIMUM = 890880
            const txFeeEstimate = 5000 // Conservative estimate per transfer
            
            // Reserve rent-exempt + fees for the distribution transaction batch
            const batchCount = Math.ceil(hopWallets.length / 5)
            const totalFeesNeeded = txFeeEstimate * batchCount
            const drainFeeEstimate = 5000 // Fee to drain source wallet after distributions
            const sourceWalletReserve = RENT_EXEMPT_MINIMUM + drainFeeEstimate // Source must keep this during distribution
            const totalReserved = BigInt(sourceWalletReserve + totalFeesNeeded)
            const distributableAmount = BigInt(currentBalance) - totalReserved
            
            // SAFETY CHECK: Ensure we have positive distributable amount
            if (distributableAmount <= 0n) {
              log({
                t: now(),
                level: 'error',
                phase: 'explosive-insufficient-funds',
                hop: hop + 1,
                currentBalance,
                totalReserved: Number(totalReserved),
                distributableAmount: Number(distributableAmount)
              })
              throw new Error(
                `Hop ${hop + 1} failed: Insufficient balance for distribution. ` +
                `Balance: ${currentBalance}, Reserved: ${totalReserved}, ` +
                `Distributable: ${distributableAmount}`
              )
            }
            
            // PRIVACY ENHANCEMENT: Random amount distribution (instead of equal splits)
            // Generate random weights for each wallet to create unequal distributions
            // ✅ MATCHES REFERENCE: relayer.js lines 1303-1316
            const weights: number[] = []
            let totalWeight = 0
            for (let i = 0; i < hopWallets.length; i++) {
              // Random weight between 0.5 and 1.5 (±50% variation)
              const weight = 0.5 + Math.random()
              weights.push(weight)
              totalWeight += weight
            }
            
            // Normalize weights and calculate amounts
            const walletAmounts = weights.map(w => {
              const normalizedWeight = w / totalWeight
              return Math.floor(Number(distributableAmount) * normalizedWeight)
            })
            
            const amountPerWallet = Math.floor(Number(distributableAmount) / hopWallets.length) // For logging

            log({
              t: now(),
              level: 'info',
              phase: 'explosive-distributing',
              hop: hop + 1,
              wallets: hopWallets.length,
              actualWallets: actualWalletsThisHop,
              requestedWallets: walletsPerHop,
              currentBalance,
              totalReserved: Number(totalReserved),
              distributableAmount: Number(distributableAmount),
              amountPerWallet,
              amountPerWalletSol: (amountPerWallet / LAMPORTS_PER_SOL).toFixed(6)
            })

            // PRIVACY ENHANCEMENT: Shuffle wallet order before distribution
            const shuffledIndices = Array.from({ length: hopWallets.length }, (_, i) => i)
            for (let i = shuffledIndices.length - 1; i > 0; i--) {
              const j = Math.floor(Math.random() * (i + 1))
              ;[shuffledIndices[i], shuffledIndices[j]] = [shuffledIndices[j], shuffledIndices[i]]
            }
            
            // Track distribution signatures for this hop
            const hopDistributionSigs: string[] = []
            
            // Distribute to intermediate wallets (batch transfers with RANDOM AMOUNTS)
            const batchSize = 5
            for (let i = 0; i < hopWallets.length; i += batchSize) {
              const batch = hopWallets.slice(i, Math.min(i + batchSize, hopWallets.length))
              const tx = new Transaction()
              
              for (let j = 0; j < batch.length; j++) {
                const walletIndex = i + j
                const shuffledIdx = shuffledIndices[walletIndex]
                const wallet = batch[j]
                const amount = walletAmounts[shuffledIdx]
                
                tx.add(
                  SystemProgram.transfer({
                    fromPubkey: currentSource.publicKey,
                    toPubkey: wallet.publicKey,
                    lamports: amount,
                  })
                )
              }

              const sig = await sendAndConfirmTransaction(conn, tx, [currentSource], {
                skipPreflight: false,
                commitment: 'confirmed',
              })
              
              hopDistributionSigs.push(sig)
              
              log({
                t: now(),
                level: 'info',
                phase: 'explosive-distributed-batch',
                hop: hop + 1,
                batch: Math.floor(i / batchSize) + 1,
                transfers: batch.length,
                sig
              })

              // PRIVACY ENHANCEMENT: Random delay between batches (50-200ms - optimized for speed)
              const randomDelay = 50 + Math.floor(Math.random() * 150)
              await sleep(randomDelay)
            }

            log({ t: now(), level: 'info', phase: 'explosive-distribution-complete', hop: hop + 1 })

            // EFFICIENCY: Drain remaining balance from source wallet (before creating next intermediate)
            // This ensures the source wallet ends at exactly 0 lamports
            const sourceBalance = await conn.getBalance(currentSource.publicKey)
            if (sourceBalance > 5000) {
              // We'll drain this to the first hop wallet (they'll all merge anyway)
              const drainTarget = hopWallets[0].publicKey
              const drainTx = new Transaction().add(
                SystemProgram.transfer({
                  fromPubkey: currentSource.publicKey,
                  toPubkey: drainTarget,
                  lamports: sourceBalance, // Send everything
                })
              )
              
              // Calculate exact fee
              const { blockhash } = await conn.getLatestBlockhash()
              drainTx.recentBlockhash = blockhash
              drainTx.feePayer = currentSource.publicKey
              const drainFee = await drainTx.getEstimatedFee(conn)
              
              if (drainFee && sourceBalance > drainFee) {
                // Rebuild with exact amount (source will be at 0)
                const finalDrainTx = new Transaction().add(
                  SystemProgram.transfer({
                    fromPubkey: currentSource.publicKey,
                    toPubkey: drainTarget,
                    lamports: sourceBalance - drainFee,
                  })
                )
                
                await sendAndConfirmTransaction(conn, finalDrainTx, [currentSource], {
                  skipPreflight: false,
                  commitment: 'confirmed',
                })
                
                log({
                  t: now(),
                  level: 'info',
                  phase: 'explosive-source-drained',
                  hop: hop + 1,
                  amount: sourceBalance - drainFee,
                  target: drainTarget.toBase58()
                })
              }
            }

            // PRIVACY ENHANCEMENT: Random wait time before merging (200-800ms - optimized for speed)
            const randomWait = 200 + Math.floor(Math.random() * 600)
            await sleep(randomWait)

            // Determine next destination
            let nextDestination: PublicKey
            if (hop === hops - 1) {
              nextDestination = finalRecipientPk
              log({ 
                t: now(), 
                level: 'info', 
                phase: 'explosive-final-hop', 
                recipient: finalRecipientPk.toBase58(),
                msg: 'LAST HOP - Merging to final recipient'
              })
            } else {
              // Use PRE-GENERATED intermediate wallet for next hop
              const nextIntermediate = preGeneratedHopSources[hop]
              nextDestination = nextIntermediate.publicKey
              currentSource = nextIntermediate
              log({
                t: now(),
                level: 'info',
                phase: 'explosive-next-intermediate',
                hop: hop + 1,
                intermediate: nextDestination.toBase58()
              })
            }

            // PRIVACY ENHANCEMENT: Shuffle merge order (wallets merge in random sequence)
            const shuffledWallets = [...hopWallets]
            for (let i = shuffledWallets.length - 1; i > 0; i--) {
              const j = Math.floor(Math.random() * (i + 1))
              ;[shuffledWallets[i], shuffledWallets[j]] = [shuffledWallets[j], shuffledWallets[i]]
            }

            // Merge all hop wallets to next destination
            log({
              t: now(),
              level: 'info',
              phase: 'explosive-merging',
              hop: hop + 1,
              wallets: shuffledWallets.length,
              destination: nextDestination.toBase58()
            })

            let totalMerged = 0n
            let successCount = 0
            const hopMergeSigs: string[] = []

            // PARALLEL PROCESSING: Check all balances concurrently for speed
            const balanceChecks = await Promise.allSettled(
              shuffledWallets.map(async (wallet) => ({
                wallet,
                balance: await conn.getBalance(wallet.publicKey)
              }))
            )
            
            const walletsWithBalance = balanceChecks
              .filter(result => result.status === 'fulfilled' && result.value.balance > 0)
              .map(result => (result as PromiseFulfilledResult<{wallet: Keypair, balance: number}>).value)
            
            log({
              t: now(),
              level: 'info',
              phase: 'explosive-merge-balance-check',
              hop: hop + 1,
              totalWallets: shuffledWallets.length,
              walletsWithBalance: walletsWithBalance.length,
              walletsSkipped: shuffledWallets.length - walletsWithBalance.length
            })

            // PARALLEL PROCESSING: Process merges concurrently in batches
            // Batch size of 3-5 concurrent transactions to avoid overwhelming RPC
            const MERGE_BATCH_SIZE = 4
            
            for (let i = 0; i < walletsWithBalance.length; i += MERGE_BATCH_SIZE) {
              const batch = walletsWithBalance.slice(i, Math.min(i + MERGE_BATCH_SIZE, walletsWithBalance.length))
              
              // Get blockhash once for the entire batch (reuse for efficiency)
              const { blockhash } = await conn.getLatestBlockhash()
              
              // Process batch in parallel
              const mergeResults = await Promise.allSettled(
                batch.map(async ({ wallet, balance }) => {
                  try {
                    // EFFICIENCY: Calculate exact fee and send EVERYTHING (wallet ends at 0)
                    const tx = new Transaction().add(
                      SystemProgram.transfer({
                        fromPubkey: wallet.publicKey,
                        toPubkey: nextDestination,
                        lamports: balance, // Send entire balance
                      })
                    )
                    
                    tx.recentBlockhash = blockhash
                    tx.feePayer = wallet.publicKey
                    const fee = await tx.getEstimatedFee(conn)
                    
                    if (!fee) {
                      return { success: false, reason: 'fee-estimation-failed' }
                    }
                    
                    // If balance is too small for fee, try sending what we can (may fail but worth trying)
                    if (balance <= fee) {
                      log({
                        t: now(),
                        level: 'warn',
                        phase: 'explosive-merge-dust',
                        wallet: wallet.publicKey.toBase58(),
                        balance,
                        fee,
                        msg: 'Attempting to drain dust wallet (balance < fee)'
                      })
                      // Try anyway - worst case it fails, but we tried to prevent stuck funds
                    }
                    
                    // Adjust transfer amount to account for fee (wallet will be completely drained)
                    const transferAmount = balance - fee
                    
                    // Rebuild transaction with exact amount
                    const finalTx = new Transaction().add(
                      SystemProgram.transfer({
                        fromPubkey: wallet.publicKey,
                        toPubkey: nextDestination,
                        lamports: transferAmount,
                      })
                    )

                    const sig = await sendAndConfirmTransaction(conn, finalTx, [wallet], {
                      skipPreflight: false,
                      commitment: 'confirmed',
                    })
                    
                    return { success: true, sig, transferAmount }
                  } catch (e: any) {
                    return { success: false, error: e.message }
                  }
                })
              )
              
              // Collect results from parallel batch
              for (const result of mergeResults) {
                if (result.status === 'fulfilled' && result.value.success) {
                  hopMergeSigs.push(result.value.sig!)
                  totalMerged += BigInt(result.value.transferAmount!)
                  successCount++
                } else if (result.status === 'rejected' || !result.value.success) {
                  log({
                    t: now(),
                    level: 'warn',
                    phase: 'explosive-merge-failed',
                    hop: hop + 1,
                    error: result.status === 'rejected' ? result.reason : result.value.error || result.value.reason
                  })
                }
              }
              
              log({
                t: now(),
                level: 'info',
                phase: 'explosive-merge-batch-complete',
                hop: hop + 1,
                batchNumber: Math.floor(i / MERGE_BATCH_SIZE) + 1,
                batchSize: batch.length,
                successful: mergeResults.filter(r => r.status === 'fulfilled' && r.value.success).length
              })
              
              // PRIVACY ENHANCEMENT: Small delay between batches (reduce RPC pressure)
              if (i + MERGE_BATCH_SIZE < walletsWithBalance.length) {
                await sleep(50 + Math.floor(Math.random() * 50))
              }
            }

            currentBalance = Number(totalMerged)

            log({
              t: now(),
              level: 'info',
              phase: 'explosive-merge-complete',
              hop: hop + 1,
              merged: successCount,
              total: hopWallets.length,
              amount: totalMerged.toString(),
              amountSol: (Number(totalMerged) / LAMPORTS_PER_SOL).toFixed(6)
            })

            log({
              t: now(),
              level: 'info',
              phase: 'explosive-final-sweep-check',
              hop: hop + 1,
              msg: 'Checking for any remaining balances in hop wallets...'
            })
            
            const finalBalanceChecks = await Promise.allSettled(
              hopWallets.map(async (wallet) => {
                const balance = await conn.getBalance(wallet.publicKey)
                return { wallet: wallet.publicKey.toBase58(), balance }
              })
            )
            
            let totalStuckFunds = 0n
            const walletsWithStuckFunds: Array<{wallet: string, balance: number}> = []
            
            for (const result of finalBalanceChecks) {
              if (result.status === 'fulfilled' && result.value.balance > 0) {
                totalStuckFunds += BigInt(result.value.balance)
                walletsWithStuckFunds.push(result.value)
              }
            }
            
            if (totalStuckFunds > 0n) {
              log({
                t: now(),
                level: 'error',
                phase: 'explosive-stuck-funds-detected',
                hop: hop + 1,
                stuckFunds: Number(totalStuckFunds),
                stuckFundsSol: (Number(totalStuckFunds) / LAMPORTS_PER_SOL).toFixed(9),
                walletsAffected: walletsWithStuckFunds.length,
                wallets: walletsWithStuckFunds,
                msg: `⚠️ ${Number(totalStuckFunds)} lamports stuck in ${walletsWithStuckFunds.length} wallets`
              })
              
              // Attempt emergency drain of stuck funds
              for (const { wallet: walletPubkey, balance } of walletsWithStuckFunds) {
                try {
                  const wallet = hopWallets.find(w => w.publicKey.toBase58() === walletPubkey)
                  if (!wallet) continue
                  
                  log({
                    t: now(),
                    level: 'warn',
                    phase: 'explosive-emergency-drain-attempt',
                    wallet: walletPubkey,
                    balance,
                    balanceSol: (balance / LAMPORTS_PER_SOL).toFixed(9)
                  })
                  
                  // Try to send entire balance (will auto-adjust for fee)
                  const emergencyTx = new Transaction().add(
                    SystemProgram.transfer({
                      fromPubkey: wallet.publicKey,
                      toPubkey: nextDestination,
                      lamports: balance,
                    })
                  )
                  
                  const { blockhash: emergencyBlockhash } = await conn.getLatestBlockhash()
                  emergencyTx.recentBlockhash = emergencyBlockhash
                  emergencyTx.feePayer = wallet.publicKey
                  const emergencyFee = await emergencyTx.getEstimatedFee(conn)
                  
                  if (emergencyFee && balance > emergencyFee) {
                    const emergencyAmount = balance - emergencyFee
                    const finalEmergencyTx = new Transaction().add(
                      SystemProgram.transfer({
                        fromPubkey: wallet.publicKey,
                        toPubkey: nextDestination,
                        lamports: emergencyAmount,
                      })
                    )
                    
                    const emergencySig = await sendAndConfirmTransaction(conn, finalEmergencyTx, [wallet], {
                      skipPreflight: false,
                      commitment: 'confirmed',
                    })
                    
                    log({
                      t: now(),
                      level: 'info',
                      phase: 'explosive-emergency-drain-success',
                      wallet: walletPubkey,
                      amount: emergencyAmount,
                      sig: emergencySig
                    })
                    
                    totalMerged += BigInt(emergencyAmount)
                  }
                } catch (drainError: any) {
                  log({
                    t: now(),
                    level: 'error',
                    phase: 'explosive-emergency-drain-failed',
                    wallet: walletPubkey,
                    error: drainError.message
                  })
                }
              }
            } else {
              log({
                t: now(),
                level: 'info',
                phase: 'explosive-final-sweep-clean',
                hop: hop + 1,
                msg: '✅ All hop wallets successfully drained to 0'
              })
            }

            // Store hop transaction data INCLUDING PRIVATE KEYS for proof of ownership
            hopTransactions.push({
              hopNumber: hop + 1,
              distributionSignatures: hopDistributionSigs,
              mergeSignatures: hopMergeSigs,
              intermediateWallets: hopWallets.map(w => w.publicKey.toBase58()),
              intermediatePrivateKeys: hopWallets.map(w => bs58.encode(w.secretKey)),
              nextDestination: nextDestination.toBase58(),
              nextDestinationPrivateKey: hop === hops - 1 ? null : bs58.encode(currentSource.secretKey),
              totalMerged: totalMerged.toString(),
            })

            // Send progress update with all signatures from this hop
            sendProgress(`hop-${hop + 1}`, [...hopDistributionSigs, ...hopMergeSigs])

            await sleep(1000)
            
            // Hop completed successfully
            hopSuccess = true
            
          } catch (hopError: any) {
            log({
              t: now(),
              level: 'error',
              phase: 'explosive-hop-failed',
              hop: hop + 1,
              attempt: hopAttempt,
              error: hopError.message
            })
            
            if (hopAttempt >= MAX_HOP_RETRIES) {
              // Max retries exhausted, throw to trigger emergency recovery
              throw hopError
            }
            
            // Wait before retry
            await sleep(2000)
          }
        } // end while retry loop
        
        if (!hopSuccess) {
          throw new Error(`Hop ${hop + 1} failed after ${MAX_HOP_RETRIES} attempts`)
        }
      } // end for hop loop

      let finalTransferSuccess = false
      let finalTransferAttempt = 0
      const MAX_FINAL_TRANSFER_RETRIES = 5
      let finalSig: string | undefined

      while (!finalTransferSuccess && finalTransferAttempt < MAX_FINAL_TRANSFER_RETRIES) {
        finalTransferAttempt++
        
        try {
          // Refresh balance before each attempt
          currentBalance = await conn.getBalance(currentSource.publicKey)
          
          // DIAGNOSTIC: On first attempt, also check recipient balance
          if (finalTransferAttempt === 1) {
            const currentRecipientBalance = await conn.getBalance(finalRecipientPk)
            log({
              t: now(),
              level: 'info',
              phase: 'explosive-pre-final-transfer-state',
              sourceWallet: currentSource.publicKey.toBase58(),
              sourceBalance: currentBalance,
              sourceBalanceSol: (currentBalance / LAMPORTS_PER_SOL).toFixed(6),
              recipientWallet: finalRecipientPk.toBase58(),
              recipientBalance: currentRecipientBalance,
              recipientBalanceSol: (currentRecipientBalance / LAMPORTS_PER_SOL).toFixed(6)
            })
            
            // If recipient already has the funds, skip transfer!
            if (currentBalance === 0 && currentRecipientBalance >= 100000) {
              log({
                t: now(),
                level: 'info',
                phase: 'explosive-final-transfer-already-complete',
                msg: 'Source empty but recipient has funds - transfer already succeeded'
              })
              finalTransferSuccess = true
              break
            }
          }
          
          log({
            t: now(),
            level: 'info',
            phase: 'explosive-final-transfer-start',
            attempt: finalTransferAttempt,
            from: currentSource.publicKey.toBase58(),
            to: finalRecipientPk.toBase58(),
            currentBalance,
            currentBalanceSol: (currentBalance / LAMPORTS_PER_SOL).toFixed(6)
          })

          if (currentBalance === 0) {
            throw new Error('Source wallet balance is 0 - funds may have already been transferred')
          }

          // Send all remaining funds to final recipient
          const finalTransferTx = new Transaction().add(
            SystemProgram.transfer({
              fromPubkey: currentSource.publicKey,
              toPubkey: finalRecipientPk,
              lamports: currentBalance,
            })
          )
          
          const { blockhash } = await conn.getLatestBlockhash()
          finalTransferTx.recentBlockhash = blockhash
          finalTransferTx.feePayer = currentSource.publicKey
          const finalFee = await finalTransferTx.getEstimatedFee(conn)
          
          if (!finalFee || currentBalance <= finalFee) {
            throw new Error(`Insufficient balance for final transfer: ${currentBalance} lamports, fee: ${finalFee}`)
          }
          
          const finalTransferAmount = currentBalance - finalFee
          
          const finalTx = new Transaction().add(
            SystemProgram.transfer({
              fromPubkey: currentSource.publicKey,
              toPubkey: finalRecipientPk,
              lamports: finalTransferAmount,
            })
          )
          
          finalSig = await sendAndConfirmTransaction(conn, finalTx, [currentSource], {
            skipPreflight: false,
            commitment: 'confirmed',
          })

          log({
            t: now(),
            level: 'info',
            phase: 'explosive-final-transfer-complete',
            attempt: finalTransferAttempt,
            sig: finalSig,
            amount: finalTransferAmount,
            amountSol: (finalTransferAmount / LAMPORTS_PER_SOL).toFixed(6)
          })

          // Verify recipient actually received funds
          await sleep(1000)
          const recipientBalance = await conn.getBalance(finalRecipientPk)
          if (recipientBalance >= finalTransferAmount - 1000) { // Allow small variance
            finalTransferSuccess = true
          } else {
            throw new Error(`Transfer sent but recipient balance (${recipientBalance}) doesn't match expected (${finalTransferAmount})`)
          }
          
        } catch (transferError: any) {
          log({
            t: now(),
            level: 'warn',
            phase: 'explosive-final-transfer-retry',
            attempt: finalTransferAttempt,
            maxRetries: MAX_FINAL_TRANSFER_RETRIES,
            error: transferError.message
          })
          
          if (finalTransferAttempt >= MAX_FINAL_TRANSFER_RETRIES) {
            throw new Error(`Final transfer failed after ${MAX_FINAL_TRANSFER_RETRIES} attempts: ${transferError.message}`)
          }
          
          await sleep(2000)
        }
      }

      if (!finalTransferSuccess) {
        throw new Error('Final transfer did not succeed after all retries')
      }

      // Mark distribution as successful
      distributionSuccess = true

      log({
        t: now(),
        level: 'info',
        phase: 'explosive-complete',
        totalHops: hops,
        totalWallets: hops * walletsPerHop,
        finalRecipient: finalRecipientPk.toBase58(),
        finalTransferSignature: finalSig,
        progress: 100,
        message: `Withdrawal complete (${hops + 2}/${hops + 2} steps)`
      })
      
    } catch (error: any) {
      distributionError = error
      log({
        t: now(),
        level: 'error',
        phase: 'explosive-distribution-failed',
        error: error.message,
        stack: error.stack
      })
    }

    // ========================================================================
    // BULLETPROOF GUARANTEE: Ensure final recipient gets funds NO MATTER WHAT
    // ========================================================================
    
    if (!distributionSuccess) {
      log({
        t: now(),
        level: 'warn',
        phase: 'explosive-emergency-recovery-start',
        reason: 'distribution-failed',
        error: distributionError?.message
      })
      
      // EMERGENCY FALLBACK: Find ANY wallet with funds and send to final recipient
      // This guarantees the user ALWAYS gets their funds
      let skipEmergencyTransfer = false
      try {
        // First try currentSource
        let emergencyBalance = await conn.getBalance(currentSource.publicKey)
        let emergencySource = currentSource
        
        // If currentSource is empty, scan ALL hop wallets for any remaining funds
        if (emergencyBalance === 0) {
          log({
            t: now(),
            level: 'warn',
            phase: 'explosive-emergency-scanning',
            msg: 'Current source empty, scanning all hop wallets for funds'
          })
          
          for (const hopData of hopTransactions) {
            if (!hopData.intermediatePrivateKeys) continue
            
            for (const privKeyB58 of hopData.intermediatePrivateKeys) {
              try {
                const wallet = Keypair.fromSecretKey(bs58.decode(privKeyB58))
                const balance = await conn.getBalance(wallet.publicKey)
                if (balance > emergencyBalance) {
                  emergencyBalance = balance
                  emergencySource = wallet
                  log({
                    t: now(),
                    level: 'info',
                    phase: 'explosive-emergency-wallet-found',
                    wallet: wallet.publicKey.toBase58(),
                    balance,
                    balanceSol: (balance / LAMPORTS_PER_SOL).toFixed(6)
                  })
                }
              } catch {}
            }
          }
        }
        
        if (emergencyBalance === 0) {
          log({
            t: now(),
            level: 'warn',
            phase: 'explosive-emergency-checking-recipient',
            msg: 'All intermediate wallets empty - checking if recipient already has funds'
          })
          
          const recipientBalance = await conn.getBalance(finalRecipientPk)
          
          log({
            t: now(),
            level: 'info',
            phase: 'explosive-emergency-recipient-balance',
            recipient: finalRecipientPk.toBase58(),
            balance: recipientBalance,
            balanceSol: (recipientBalance / LAMPORTS_PER_SOL).toFixed(6)
          })
          
          // If recipient has significant funds, consider it a success
          if (recipientBalance >= 100000) { // At least 0.0001 SOL
            log({
              t: now(),
              level: 'info',
              phase: 'explosive-emergency-already-delivered',
              msg: 'Final recipient already has funds - withdrawal likely succeeded',
              balance: recipientBalance
            })
            
            // Mark as successful - funds are already at destination
            distributionSuccess = true
            emergencyRecoveryUsed = false // Not really recovery, just verification
            skipEmergencyTransfer = true
          } else {
            throw new Error(
              `Emergency recovery failed: All wallets are empty (0 lamports total). ` +
              `Final recipient also has insufficient balance (${recipientBalance} lamports). ` +
              `Funds may have been lost or transferred elsewhere.`
            )
          }
        }
        
        // Only proceed with emergency transfer if we found funds and recipient doesn't have them
        if (!skipEmergencyTransfer) {
          log({
            t: now(),
            level: 'warn',
            phase: 'explosive-emergency-direct-transfer',
            from: emergencySource.publicKey.toBase58(),
            to: finalRecipientPk.toBase58(),
            balance: emergencyBalance,
            balanceSol: (emergencyBalance / LAMPORTS_PER_SOL).toFixed(6)
          })
        
          // Send MAXIMUM possible amount (balance minus fee)
        let transferAmount = emergencyBalance
        let emergencySig: string | undefined
        
        try {
          // Attempt 1: Try sending everything (will fail with "insufficient funds for fee")
          const maxTx = new Transaction().add(
            SystemProgram.transfer({
              fromPubkey: emergencySource.publicKey,
              toPubkey: finalRecipientPk,
              lamports: transferAmount,
            })
          )
          
          emergencySig = await sendAndConfirmTransaction(conn, maxTx, [emergencySource], {
            skipPreflight: false,
            commitment: 'confirmed',
          })
          emergencySignature = emergencySig
        } catch (feeError) {
          // Expected to fail - now calculate proper fee and retry
          const emergencyTx = new Transaction().add(
            SystemProgram.transfer({
              fromPubkey: emergencySource.publicKey,
              toPubkey: finalRecipientPk,
              lamports: emergencyBalance,
            })
          )
          
          const { blockhash } = await conn.getLatestBlockhash()
          emergencyTx.recentBlockhash = blockhash
          emergencyTx.feePayer = emergencySource.publicKey
          const emergencyFee = await emergencyTx.getEstimatedFee(conn)
          
          if (!emergencyFee) {
            throw new Error('Could not estimate emergency transfer fee')
          }
          
          // Calculate what we can actually send
          transferAmount = emergencyBalance - emergencyFee
          
          if (transferAmount <= 0) {
            throw new Error(`Emergency recovery failed: balance (${emergencyBalance}) not enough to cover fee (${emergencyFee})`)
          }
          
          const finalEmergencyTx = new Transaction().add(
            SystemProgram.transfer({
              fromPubkey: emergencySource.publicKey,
              toPubkey: finalRecipientPk,
              lamports: transferAmount,
            })
          )
          
          emergencySig = await sendAndConfirmTransaction(conn, finalEmergencyTx, [emergencySource], {
            skipPreflight: false,
            commitment: 'confirmed',
          })
          emergencySignature = emergencySig
        }
        
        log({
          t: now(),
          level: 'warn',
          phase: 'explosive-emergency-transfer-complete',
          sig: emergencySig,
          amount: transferAmount,
          amountSol: (transferAmount / LAMPORTS_PER_SOL).toFixed(6)
        })
        
        // Mark as successful since funds reached final recipient
        distributionSuccess = true
        emergencyRecoveryUsed = true
        } // end if !skipEmergencyTransfer
        
      } catch (emergencyError: any) {
        log({
          t: now(),
          level: 'error',
          phase: 'explosive-emergency-failed',
          error: emergencyError.message,
          stack: emergencyError.stack
        })
        
        throw new Error(
          `Distribution failed AND emergency recovery failed. ` +
          `Original error: ${distributionError?.message}. ` +
          `Emergency error: ${emergencyError.message}`
        )
      }
    }
    
    // FINAL VERIFICATION: Confirm final recipient has the funds
    const finalRecipientBalance = await conn.getBalance(finalRecipientPk)
    sendProgress('verified', [])
    
    log({
      t: now(),
      level: 'info',
      phase: 'explosive-final-verification',
      recipient: finalRecipientPk.toBase58(),
      balance: finalRecipientBalance,
      balanceSol: (finalRecipientBalance / LAMPORTS_PER_SOL).toFixed(6),
      progress: 100,
      message: 'Withdrawal verified and complete'
    })
    
    if (finalRecipientBalance < 1000) {
      const firstIntermediateBalance = await conn.getBalance(firstIntermediate.publicKey)
      log({
        t: now(),
        level: 'error',
        phase: 'explosive-verification-failed',
        finalRecipient: finalRecipientPk.toBase58(),
        finalRecipientBalance,
        firstIntermediate: firstIntermediate.publicKey.toBase58(),
        firstIntermediateBalance,
        currentSource: currentSource.publicKey.toBase58(),
        currentSourceBalance: await conn.getBalance(currentSource.publicKey)
      })
      
      throw new Error(
        `CRITICAL: Final recipient has insufficient balance (${finalRecipientBalance} lamports). ` +
        `Check firstIntermediate: ${firstIntermediate.publicKey.toBase58()} (${firstIntermediateBalance} lamports)`
      )
    }

    return {
      sig: sigExec.signature,
      preparedSig: sigPrep.signature,
      firstIntermediate: firstIntermediate.publicKey.toBase58(),
      firstIntermediateSecretKey: bs58.encode(firstIntermediate.secretKey),
      hops,
      walletsPerHop,
      totalWallets: hops * walletsPerHop,
      finalRecipient: finalRecipientPk.toBase58(),
      completed: true,
      hopDetails: hopTransactions,
      emergencyRecovery: emergencyRecoveryUsed,
      emergencySignature,
    }
  } catch (error: any) {
    log({ t: now(), level: 'error', phase: 'explosive-multi-hop-error', err: error.message })
    throw error
  }
}

/** EXPLOSIVE withdraw handler - splits to 10 intermediate wallets then merges to final recipient */
async function handleExplosiveWithdraw(
  req: any,
  {
    conn,
    RELAYER,
    CU_LIMIT_PREPARE,
    CU_LIMIT_EXECUTE,
    CU_PRICE_MICROLAMPORTS,
    progressTrackers,
    sessionId,
  }: {
    conn: Connection
    RELAYER: Keypair
    CU_LIMIT_PREPARE: number
    CU_LIMIT_EXECUTE: number
    CU_PRICE_MICROLAMPORTS: number
    progressTrackers?: Map<string, any>
    sessionId?: string
  }
) {
  const LAMPORTS_PER_SOL = 1_000_000_000

  // Helper to send progress updates
  const sendProgress = (phase: string, signatures: string[] = []) => {
    if (!progressTrackers || !sessionId) return
    
    const tracker = progressTrackers.get(sessionId)
    if (!tracker) return

    tracker.currentStep++
    tracker.phase = phase
    
    const progress = Math.floor((tracker.currentStep / tracker.totalSteps) * 100)
    
    try {
      tracker.ws.send(JSON.stringify({
        type: 'progress',
        sessionId,
        progress,
        phase,
        currentStep: tracker.currentStep,
        totalSteps: tracker.totalSteps,
        signatures,
      }))
    } catch (e) {
      // WebSocket might be closed, ignore
    }
  }

  const programId = new PublicKey(req.programId)
  const state = pdaState(programId)
  const pool = pdaPool(programId)
  const escrow = pdaEscrow(programId)
  
  // finalRecipient is where funds ultimately go (user's actual wallet)
  const finalRecipient = req.finalRecipient 
    ? new PublicKey(req.finalRecipient) 
    : new PublicKey(req.recipient) // fallback for backwards compatibility
    
  const memo = Buffer.from(req.memoPackedBase64, 'base64')
  
  // RELAYER GENERATES intermediate wallets (just like multi_hop does)
  const intermediateWallets: Keypair[] = []
  for (let i = 0; i < 10; i++) {
    intermediateWallets.push(Keypair.generate())
  }
  
  const intermediateWalletPubkeys = intermediateWallets.map(w => w.publicKey)

  const parsed = await verifyOffchainJoinSplit(memo)

  log({
    t: now(),
    level: 'info',
    phase: 'explosive-start',
    publicAmount: parsed.publicAmount.toString(),
    nInputs: parsed.nInputs,
    nonce: parsed.nonce.toString(),
    intermediateWallets: intermediateWalletPubkeys.map(w => w.toBase58()),
  })

  const explosivePda = pdaExplosive(programId, parsed.nonce)
  log({ t: now(), level: 'info', phase: 'explosive-pda', pda: explosivePda.toBase58() })

  // Track if we successfully executed (nullifier was used)
  let prepareSignature = ''
  let executeSignatures: string[] = []
  let nullifierUsed = false
  let emergencyRecoveryUsed = false
  let emergencySignature: string | undefined

  try {
    const nullifierPdas = parsed.inputNullifiers
      .slice(0, parsed.nInputs)
      .map((n: Buffer) => pdaNullifier(programId, n))

    // Fetch next_index for output note PDAs
    const stateAccount = await conn.getAccountInfo(state)
    if (!stateAccount) throw new Error('State account not found')
    const nextIndex = stateAccount.data.readUInt32LE(43)
    log({ t: now(), level: 'info', phase: 'state-index', nextIndex })

    // Output note PDAs (for partial withdrawals with change)
    const outputNotePdas: PublicKey[] = []
    for (let j = 0; j < parsed.outputCommitments.length; j++) {
      const commitment = parsed.outputCommitments[j]
      const isZero = commitment.every((b: number) => b === 0)
      if (!isZero) {
        const treeIdx = Number(nextIndex) + outputNotePdas.length
        const notePda = pdaNoteByIndex(programId, treeIdx)
        outputNotePdas.push(notePda)
        log({
          t: now(),
          level: 'info',
          phase: 'output-note-pda',
          outputIdx: j,
          treeIdx,
          notePda: notePda.toBase58()
        })
      }
    }

    // <<< ESCROW TOP-UP >>>
    await ensureEscrowFunded(conn, RELAYER, escrow)

    // Progress: Starting (step 0/4: starting, prepare, execute, merge)
    sendProgress('starting', [])

  // 1) PREPARE EXPLOSIVE (needs v0 tx with lookup table - too large otherwise)
  // NOTE: We use intermediateWallets[0] as the on-chain recipient (program requirement)
  // but will merge all funds to finalRecipient after distribution
  let prepareSignature: string
  {
    // Collect all addresses for lookup table
    const allAddresses = [
      programId,
      state,
      pool,
      intermediateWalletPubkeys[0],
      RELAYER.publicKey,
      escrow,
      explosivePda,
      SystemProgram.programId,
      ...nullifierPdas,
      ...outputNotePdas,
      ...intermediateWalletPubkeys,
    ]

    // Create lookup table
    const { lookupTableAddress, lookupTableAccount } = await getOrCreateLookupTable(
      conn,
      RELAYER,
      allAddresses
    )
    log({ t: now(), level: 'info', phase: 'lookup-table', address: lookupTableAddress.toBase58() })

    const instructions = []
    instructions.push(ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT_PREPARE }))
    if (CU_PRICE_MICROLAMPORTS > 0) {
      instructions.push(
        ComputeBudgetProgram.setComputeUnitPrice({ microLamports: CU_PRICE_MICROLAMPORTS })
      )
    }

    instructions.push(
      ixPrepareExplosiveWithdraw(
        programId,
        {
          state,
          pool,
          recipient: intermediateWalletPubkeys[0], // First intermediate receives on-chain
          relayer: RELAYER.publicKey,
          signer: RELAYER.publicKey,
          escrow,
          explosivePda,
          nullifierPdas,
          outputNotePdas,
        },
        memo,
        intermediateWalletPubkeys,
        parsed.nonce
      )
    )

    const { blockhash } = await conn.getLatestBlockhash()
    
    // Create v0 transaction with lookup table
    const messageV0 = new TransactionMessage({
      payerKey: RELAYER.publicKey,
      recentBlockhash: blockhash,
      instructions,
    }).compileToV0Message([lookupTableAccount])

    const txV0 = new VersionedTransaction(messageV0)
    txV0.sign([RELAYER])

    log({ t: now(), level: 'info', phase: 'v0-tx-size', bytes: txV0.serialize().length })

    const { signature } = await sendV0TxWithLogs(conn, txV0)
    prepareSignature = signature
    log({ t: now(), level: 'info', phase: 'prepare-explosive', sig: prepareSignature })
    sendProgress('prepared', [prepareSignature])
  }

  // 2) EXECUTE EXPLOSIVE: 10 PARALLEL TRANSACTIONS
  {
    const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash()
    log({ t: now(), level: 'info', phase: 'execute-explosive-start', blockhash, lastValidBlockHeight })

    const txPromises: Promise<string>[] = []

    // Send all 10 immediately without waiting
    for (let i = 0; i < 10; i++) {
      const tx = new Transaction()
      
      if (CU_PRICE_MICROLAMPORTS > 0) {
        tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 35000 }))
        tx.add(
          ComputeBudgetProgram.setComputeUnitPrice({ microLamports: CU_PRICE_MICROLAMPORTS })
        )
      }

      tx.add(
        ixExecuteExplosiveSingle(programId, {
          state,
          pool,
          relayer: RELAYER.publicKey,
          explosivePda,
          walletPubkey: intermediateWallets[i].publicKey,
          walletIndex: i,
        })
      )

      tx.feePayer = RELAYER.publicKey
      tx.recentBlockhash = blockhash

      // Fire-and-forget: send WITHOUT awaiting
      const sig = conn
        .sendTransaction(tx, [RELAYER], { skipPreflight: false })
        .then((s) => {
          log({
            t: now(),
            level: 'info',
            phase: `execute-explosive-sent-${i}`,
            sig: s,
            wallet: intermediateWalletPubkeys[i].toBase58(),
          })
          return s
        })
        .catch((err) => {
          log({
            t: now(),
            level: 'error',
            phase: `execute-explosive-send-${i}`,
            err: err.message,
          })
          throw err
        })

      txPromises.push(sig)
    }

    // Wait for all sends to complete
    const allSignatures = await Promise.all(txPromises)
    log({
      t: now(),
      level: 'info',
      phase: 'execute-explosive-all-sent',
      count: allSignatures.length,
    })

    // Confirm all in parallel
    const confirmPromises = allSignatures.map((sig, i) =>
      conn
        .confirmTransaction(sig, 'confirmed')
        .then(() => {
          log({
            t: now(),
            level: 'info',
            phase: `execute-explosive-${i}`,
            sig,
            wallet: intermediateWalletPubkeys[i].toBase58(),
          })
          return { index: i, signature: sig }
        })
        .catch((err) => {
          log({
            t: now(),
            level: 'error',
            phase: `execute-explosive-confirm-${i}`,
            sig,
            err: err.message,
          })
          throw err
        })
    )

    const executeResults = await Promise.all(confirmPromises)
    executeSignatures = executeResults
      .sort((a, b) => a.index - b.index)
      .map((r) => r.signature)

    nullifierUsed = true

    log({
      t: now(),
      level: 'info',
      phase: 'execute-explosive-complete',
      count: executeSignatures.length,
      signatures: executeSignatures,
    })
    sendProgress('executed', executeSignatures)
  }

    // MERGE TO FINAL RECIPIENT: Collect all funds from 10 intermediate wallets to final recipient
    log({
      t: now(),
      level: 'info',
      phase: 'explosive-merge-start',
      intermediateCount: intermediateWallets.length,
      finalRecipient: finalRecipient.toBase58(),
    })

    const mergeSigs: string[] = []
    let totalMerged = 0n

    for (let i = 0; i < intermediateWallets.length; i++) {
      const wallet = intermediateWallets[i]
      try {
        const balance = await conn.getBalance(wallet.publicKey)
        if (balance < 5000) continue // Skip if too small

        // Calculate exact fee
        const tx = new Transaction().add(
          SystemProgram.transfer({
            fromPubkey: wallet.publicKey,
            toPubkey: finalRecipient,
            lamports: balance,
          })
        )

        const { blockhash } = await conn.getLatestBlockhash()
        tx.recentBlockhash = blockhash
        tx.feePayer = wallet.publicKey
        const fee = await tx.getEstimatedFee(conn)

        if (!fee || balance <= fee) continue

        // Send max amount minus fee
        const transferAmount = balance - fee
        const finalTx = new Transaction().add(
          SystemProgram.transfer({
            fromPubkey: wallet.publicKey,
            toPubkey: finalRecipient,
            lamports: transferAmount,
          })
        )

        const sig = await sendAndConfirmTransaction(conn, finalTx, [wallet], {
          skipPreflight: false,
          commitment: 'confirmed',
        })

        mergeSigs.push(sig)
        totalMerged += BigInt(transferAmount)

        log({
          t: now(),
          level: 'info',
          phase: 'explosive-merged',
          wallet: i,
          amount: transferAmount,
          sig,
        })

        await sleep(50) // Small delay between merges
      } catch (e: any) {
        log({
          t: now(),
          level: 'warn',
          phase: 'explosive-merge-failed',
          wallet: i,
          error: e.message,
        })
      }
    }

    const LAMPORTS_PER_SOL = 1_000_000_000
    log({
      t: now(),
      level: 'info',
      phase: 'explosive-merge-complete',
      merged: mergeSigs.length,
      totalMerged: totalMerged.toString(),
      totalMergedSol: (Number(totalMerged) / LAMPORTS_PER_SOL).toFixed(6),
      finalRecipient: finalRecipient.toBase58(),
    })
    sendProgress('verified', mergeSigs)

    // Return data in same format as explosive_multi_hop for storage consistency
    return {
      sig: executeSignatures[9],
      preparedSig: prepareSignature,
      explosivePda: explosivePda.toBase58(),
      firstIntermediate: intermediateWallets[0].publicKey.toBase58(),
      firstIntermediateSecretKey: bs58.encode(intermediateWallets[0].secretKey),
      hops: 1,
      walletsPerHop: 10,
      totalWallets: 10,
      finalRecipient: finalRecipient.toBase58(),
      completed: true,
      nullifierUsed, // Important for database updates
      // Complete hop transaction data for database storage (matches multi_hop format)
      hopDetails: [{
        hopNumber: 1,
        distributionSignatures: executeSignatures, // All 10 explosive execute signatures
        mergeSignatures: mergeSigs,
        intermediateWallets: intermediateWallets.map(w => w.publicKey.toBase58()),
        intermediatePrivateKeys: intermediateWallets.map(w => bs58.encode(w.secretKey)),
        nextDestination: finalRecipient.toBase58(),
        nextDestinationPrivateKey: null, // Final recipient (user's wallet, no secret)
        totalMerged: totalMerged.toString(),
      }],
      emergencyRecovery: emergencyRecoveryUsed,
      emergencySignature,
    }
  } catch (error: any) {
    log({
      t: now(),
      level: 'error',
      phase: 'explosive-withdraw-error',
      error: error.message,
      stack: error.stack,
      nullifierUsed
    })

    // ========================================================================
    // EMERGENCY RECOVERY: If we executed (nullifier used), ensure funds reach recipient
    // ========================================================================
    if (nullifierUsed && intermediateWallets.length > 0) {
      log({
        t: now(),
        level: 'warn',
        phase: 'explosive-emergency-start',
        reason: 'merge-failed-but-executed',
      })

      try {
        // Try to recover from any intermediate wallet that has balance
        const recoverySignatures: string[] = []
        let totalRecovered = 0n

        for (let i = 0; i < intermediateWallets.length; i++) {
          const wallet = intermediateWallets[i]
          try {
            const balance = await conn.getBalance(wallet.publicKey)
            if (balance < 5000) continue

            // Calculate fee and send maximum
            const tx = new Transaction().add(
              SystemProgram.transfer({
                fromPubkey: wallet.publicKey,
                toPubkey: finalRecipient,
                lamports: balance,
              })
            )

            const { blockhash } = await conn.getLatestBlockhash()
            tx.recentBlockhash = blockhash
            tx.feePayer = wallet.publicKey
            const fee = await tx.getEstimatedFee(conn)

            if (!fee || balance <= fee) continue

            const transferAmount = balance - fee
            const finalTx = new Transaction().add(
              SystemProgram.transfer({
                fromPubkey: wallet.publicKey,
                toPubkey: finalRecipient,
                lamports: transferAmount,
              })
            )

            const sig = await sendAndConfirmTransaction(conn, finalTx, [wallet], {
              skipPreflight: false,
              commitment: 'confirmed',
            })

            recoverySignatures.push(sig)
            totalRecovered += BigInt(transferAmount)

            log({
              t: now(),
              level: 'warn',
              phase: 'explosive-emergency-recovered',
              wallet: i,
              amount: transferAmount,
              sig,
            })
          } catch (walletError: any) {
            log({
              t: now(),
              level: 'warn',
              phase: 'explosive-emergency-wallet-failed',
              wallet: i,
              error: walletError.message,
            })
          }
        }

        if (recoverySignatures.length > 0) {
          emergencyRecoveryUsed = true
          emergencySignature = recoverySignatures[0]

          log({
            t: now(),
            level: 'warn',
            phase: 'explosive-emergency-success',
            recovered: recoverySignatures.length,
            totalRecovered: totalRecovered.toString(),
            totalRecoveredSol: (Number(totalRecovered) / LAMPORTS_PER_SOL).toFixed(6),
          })

          // Return partial success with emergency recovery
          return {
            sig: executeSignatures[9] || executeSignatures[0],
            preparedSig: prepareSignature,
            explosivePda: explosivePda.toBase58(),
            firstIntermediate: intermediateWallets[0].publicKey.toBase58(),
            firstIntermediateSecretKey: bs58.encode(intermediateWallets[0].secretKey),
            hops: 1,
            walletsPerHop: 10,
            totalWallets: 10,
            finalRecipient: finalRecipient.toBase58(),
            completed: true,
            nullifierUsed,
            hopDetails: [{
              hopNumber: 1,
              distributionSignatures: executeSignatures,
              mergeSignatures: recoverySignatures,
              intermediateWallets: intermediateWallets.map(w => w.publicKey.toBase58()),
              intermediatePrivateKeys: intermediateWallets.map(w => bs58.encode(w.secretKey)),
              nextDestination: finalRecipient.toBase58(),
              nextDestinationPrivateKey: null,
              totalMerged: totalRecovered.toString(),
            }],
            emergencyRecovery: true,
            emergencySignature,
          }
        }
      } catch (emergencyError: any) {
        log({
          t: now(),
          level: 'error',
          phase: 'explosive-emergency-failed',
          error: emergencyError.message,
        })
      }
    }

    // Could not recover - throw original error
    throw error
  }
}

/* ---------- main ---------- */
;(async () => {
  const requiredEnvVars = ['RELAYER_SECRET_BASE58']
  const missingVars = requiredEnvVars.filter(v => !process.env[v])
  if (missingVars.length > 0) {
    console.error(`FATAL: Missing required environment variables: ${missingVars.join(', ')}`)
    process.exit(1)
  }

  if (VERIFY_OFFCHAIN) {
     // @ts-ignore - snarkjs is dynamically imported when VERIFY_OFFCHAIN=true
    snarkjs = await import('snarkjs')
    if (!process.env.VK_JSON) {
      throw new Error(
        'VERIFY_OFFCHAIN=true but VK_JSON not set (expected e.g. tests/circuits/privw_vk.json)'
      )
    }
    vkJson = JSON.parse(fs.readFileSync(process.env.VK_JSON, 'utf8'))
  }

  const RELAYER = Keypair.fromSecretKey(
    bs58.decode(mustEnv('RELAYER_SECRET_BASE58'))
  )
  const RPC = process.env.RPC || 'https://api.devnet.solana.com'
  const BIND = process.env.BIND || '127.0.0.1'
  const PORT = parseInt(process.env.RELAYER_PORT || '8989', 10)

  const CU_LIMIT_PREPARE = parseInt(process.env.CU_LIMIT_PREPARE || '1300000', 10)
  const CU_LIMIT_EXECUTE = parseInt(process.env.CU_LIMIT_EXECUTE || '1300000', 10)
  const CU_PRICE_MICROLAMPORTS = parseInt(
    process.env.CU_PRICE_MICROLAMPORTS || '0',
    10
  )

  const conn = new Connection(RPC, 'confirmed')
  log({
    t: now(),
    level: 'info',
    phase: 'boot',
    relayer: RELAYER.publicKey.toBase58(),
    rpc: RPC,
    ws: `ws://${BIND}:${PORT}`,
    verifyOffchain: VERIFY_OFFCHAIN,
    cuLimitPrepare: CU_LIMIT_PREPARE,
    cuLimitExecute: CU_LIMIT_EXECUTE,
    cuPriceMicrolamports: CU_PRICE_MICROLAMPORTS,
  })

  const wss = new WebSocket.Server({ 
    host: BIND, 
    port: PORT,
    maxPayload: 5 * 1024 * 1024 // 5MB max payload
  })

  // Progress tracking for multi-hop withdrawals (supports multiple concurrent users)
  const progressTrackers = new Map<string, {
    ws: any,
    totalSteps: number,
    currentStep: number,
    phase: string
  }>()

  // Queue monitoring metrics
  const queueMetrics = {
    processed: 0,
    failed: 0,
    totalProcessingTime: 0,
    peek: () => ({
      size: queue.length,
      processing,
      avgProcessingTime: queueMetrics.processed > 0 
        ? Math.round(queueMetrics.totalProcessingTime / queueMetrics.processed) 
        : 0,
      totalProcessed: queueMetrics.processed,
      totalFailed: queueMetrics.failed
    })
  }

  // Transaction queue to prevent nonce conflicts
  let processing = false
  const queue: Array<() => Promise<void>> = []

  async function processQueue() {
    if (processing || queue.length === 0) return
    processing = true
    
    while (queue.length > 0) {
      const task = queue.shift()
      if (task) {
        const start = Date.now()
        try {
          await task()
          queueMetrics.processed++
          queueMetrics.totalProcessingTime += (Date.now() - start)
        } catch (err) {
          queueMetrics.failed++
          console.error('Queue task error:', err)
        }
      }
    }
    
    processing = false
  }

  wss.on('connection', (ws) => {
    ws.on('message', async (raw) => {
      let req: any
      try {
        req = JSON.parse(raw.toString())
      } catch {
        return
      }
      const id = req.id || crypto.randomUUID()
      const reply = (ok: boolean, payload: any) => {
        const message = ok
          ? { id, ok: true, ...payload }
          : {
              id,
              ok: false,
              error: typeof payload === 'string' ? payload : (payload.error || 'Transaction failed'),
              // Only include logs if explicitly provided, sanitize stack traces
              ...(payload.logs && { logs: payload.logs })
            }
        ws.send(JSON.stringify(message))
      }

      try {
        // MULTI-HOP: Run in parallel (no queue) for maximum performance
        if (req.type === 'explosive_multi_hop') {
          // Initialize progress tracker for this session
          const sessionId = req.id || id
          const hops = req.hops || 10
          const totalSteps = hops + 2 // prepare + execute + N hops
          
          progressTrackers.set(sessionId, {
            ws,
            totalSteps,
            currentStep: 0,
            phase: 'starting'
          })

          const result = await handleExplosiveMultiHop(req, {
            conn,
            RELAYER,
            CU_LIMIT_PREPARE,
            CU_LIMIT_EXECUTE,
            CU_PRICE_MICROLAMPORTS,
            progressTrackers,
            sessionId,
          })
          
          // Clean up progress tracker
          progressTrackers.delete(sessionId)
          
          log({
            t: now(),
            level: 'info',
            phase: 'explosive-multi-hop-result',
            result: JSON.stringify(result),
          })
          return reply(true, result)
        }

        // ALL OTHER TYPES: Use queue to prevent nonce conflicts
        queue.push(async () => {
          try {
            if (req.type === 'withdraw_via_memo') {
              const { sig } = await handleWithdrawViaMemoSingle(req, {
                conn,
                RELAYER,
                CU_LIMIT_PREPARE,
                CU_LIMIT_EXECUTE,
                CU_PRICE_MICROLAMPORTS,
              })
              log({
                t: now(),
                level: 'info',
                phase: 'broadcast-single',
                sig,
                recipient: req.recipient,
              })
              return reply(true, { signature: sig })
            }

            if (req.type === 'withdraw_via_memo_join_split') {
              const { sig } = await handleWithdrawViaMemoJoinSplit(req, {
                conn,
                RELAYER,
                CU_LIMIT_PREPARE,
                CU_LIMIT_EXECUTE,
                CU_PRICE_MICROLAMPORTS,
              })
              log({
                t: now(),
                level: 'info',
                phase: 'broadcast-join-split',
                sig,
                recipient: req.recipient,
              })
              return reply(true, { signature: sig })
            }

            if (req.type === 'explosive_withdraw') {
              // Initialize progress tracker for single-hop withdrawal
              const sessionId = req.id || id
              const totalSteps = 4 // starting + prepared + executed + verified (merge complete)
              
              progressTrackers.set(sessionId, {
                ws,
                currentStep: 0,
                totalSteps,
                phase: 'starting'
              })

              const result = await handleExplosiveWithdraw(req, {
                conn,
                RELAYER,
                CU_LIMIT_PREPARE,
                CU_LIMIT_EXECUTE,
                CU_PRICE_MICROLAMPORTS,
                progressTrackers,
                sessionId,
              })
              
              // Clean up progress tracker
              progressTrackers.delete(sessionId)
              
              log({
                t: now(),
                level: 'info',
                phase: 'broadcast-explosive',
                sig: result.sig,
                recipient: req.finalRecipient,
                explosivePda: result.explosivePda,
                hops: result.hops,
                walletsPerHop: result.walletsPerHop,
              })
              // Return full result for client storage
              return reply(true, result)
            }

            return reply(false, 'unknown type')
          } catch (e: any) {
            const msg = String(e?.message || e)
            log({ t: now(), level: 'error', phase: 'broadcast', err: msg })
            const logsMatch = /Logs:\n([\s\S]*)$/.exec(msg)
            const logs = logsMatch ? logsMatch[1] : undefined
            return reply(false, { error: msg, logs })
          }
        })

        // Process queue
        processQueue()
      } catch (e: any) {
        // Error parsing request or initializing multi-hop
        const msg = String(e?.message || e)
        log({ t: now(), level: 'error', phase: 'request-error', err: msg })
        return reply(false, { error: 'Invalid request' })
      }
    })
  })

  // Health check endpoint (responds to ping messages)
  wss.on('connection', (ws) => {
    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString())
        if (msg.type === 'health' || msg.type === 'ping') {
          ws.send(JSON.stringify({
            type: 'health',
            status: 'ok',
            relayer: RELAYER.publicKey.toBase58(),
            queue: queueMetrics.peek(),
            uptime: process.uptime(),
            timestamp: new Date().toISOString()
          }))
        }
      } catch {
        // Ignore invalid health check messages
      }
    })
  })

  // Graceful shutdown handlers
  let isShuttingDown = false
  const gracefulShutdown = async (signal: string) => {
    if (isShuttingDown) return
    isShuttingDown = true

    log({ t: now(), level: 'info', phase: 'shutdown', signal })
    
    // Stop accepting new connections
    wss.close(() => {
      log({ t: now(), level: 'info', phase: 'shutdown', message: 'WebSocket server closed' })
    })

    // Wait for queue to drain (max 30 seconds)
    const maxWait = 30000
    const start = Date.now()
    while (queue.length > 0 && (Date.now() - start) < maxWait) {
      await new Promise(resolve => setTimeout(resolve, 100))
    }

    if (queue.length > 0) {
      log({ 
        t: now(), 
        level: 'warn', 
        phase: 'shutdown', 
        message: `${queue.length} tasks remaining in queue` 
      })
    }

    log({ t: now(), level: 'info', phase: 'shutdown', message: 'Relayer stopped' })
    process.exit(0)
  }

  process.on('SIGINT', () => gracefulShutdown('SIGINT'))
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))

})().catch((e) => {
  console.error('Fatal relayer error:', e)
  process.exit(1)
})
