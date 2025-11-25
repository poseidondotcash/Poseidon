#!/usr/bin/env node

const WebSocket = require("ws");
const bs58 = require("bs58");
const crypto = require("crypto");
require("dotenv").config();
const N_INS = 6;   // Must match on-chain MAX_INS
const N_OUTS = 6;  // Must match on-chain MAX_OUTS
const {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  ComputeBudgetProgram,
} = require("@solana/web3.js");

const VERIFY_OFFCHAIN = /^true$/i.test(process.env.VERIFY_OFFCHAIN || "");
let snarkjs, vkJson;

const now = () => new Date().toISOString();
const log = (obj) => process.stdout.write(JSON.stringify(obj) + "\n");
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();

function mustEnv(k) {
  const v = process.env[k];
  if (!v) throw new Error(`Missing env ${k}`);
  return v;
}

function anchorIxDisc(name) {
  return sha256(Buffer.from(`global:${name}`)).subarray(0, 8);
}

function u64ToBe32(x) {
  const out = Buffer.alloc(32);
  out.writeBigUInt64BE(BigInt(x), 24);
  return out;
}

function be32ToBig(b) {
  return BigInt("0x" + Buffer.from(b).toString("hex"));
}

function pda(program, seeds) {
  return PublicKey.findProgramAddressSync(seeds, program)[0];
}

function pdaState(program) {
  return pda(program, [Buffer.from("state")]);
}
function pdaPool(program) {
  return pda(program, [Buffer.from("pool")]);
}
function pdaEscrow(program) {
  return pda(program, [Buffer.from("escrow")]);
}

function pdaPreparedSingle(program, nonceU64) {
  const be32 = Buffer.alloc(32);
  be32.writeBigUInt64BE(BigInt(nonceU64), 24);
  return pda(program, [Buffer.from("prep"), be32]);
}

function pdaPreparedJoinSplit(program, nonceU64) {
  const be32 = Buffer.alloc(32);
  be32.writeBigUInt64BE(BigInt(nonceU64), 24); // u64_to_be_32 equivalent
  return pda(program, [Buffer.from("prep"), be32]);
}

function pdaNullifier(program, noteNullifier32) {
  return pda(program, [Buffer.from("null"), Buffer.from(noteNullifier32)]);
}

function pdaNote(program, commitment32) {
  return pda(program, [Buffer.from("note"), Buffer.from(commitment32)]);
}

function pdaNoteByIndex(program, treeIndex) {
  const idxBe = Buffer.alloc(4);
  idxBe.writeUInt32BE(treeIndex, 0);
  return pda(program, [Buffer.from("note"), idxBe]);
}

function parsePackedSingle(memo) {
  let off = 0;
  const take = (n) => {
    const slice = memo.subarray(off, off + n);
    if (slice.length !== n) throw new Error("memo too short");
    off += n;
    return slice;
  };

  const A = take(64);
  const B = take(128);
  const C = take(64);
  const root = take(32);
  const publicAmount = take(8).readBigUInt64LE(0); // BigInt
  const nonce = take(8).readBigUInt64LE(0); // BigInt
  const newCommitment = take(32);
  const noteNullifier = take(32);
  const recipient = new PublicKey(take(32));
  const nChanges = take(4).readUInt32LE(0);

  const changes = [];
  for (let i = 0; i < nChanges; i++) {
    const com = take(32);
    const ctLen = take(4).readUInt32LE(0);
    const ct = take(ctLen);
    changes.push({ commitment: com, ciphertext: ct });
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
  };
}

function parsePackedJoinSplitFull(memo) {
  console.log(`[relayer] parsePackedJoinSplitFull: memo.length = ${memo.length}`);
  let off = 0;

  const take = (n) => {
    if (off + n > memo.length) {
      console.log(`[relayer] take(${n}) failed: off=${off}, memo.length=${memo.length}`);
      throw new Error("join-split memo too short");
    }
    const slice = memo.subarray(off, off + n);
    off += n;
    return slice;
  };

  const readU64LE = () => {
    const b = take(8);
    return b.readBigUInt64LE(0);
  };

  // Proof
  const proofA = take(64);
  const proofB = take(128);
  const proofC = take(64);

  // Amounts + nonce
  const publicAmount = readU64LE();
  const extAmountIn = readU64LE();
  const nonce = readU64LE();

  // nInputs
  const nInputs = take(4).readUInt32LE(0);

  // Fixed arrays: ALL input nullifiers (MAX_INS = 6)
  const inputNullifiers = [];
  for (let i = 0; i < N_INS; i++) {
    inputNullifiers.push(take(32));
  }

  // Flag
  const flag = take(1)[0];
  const isFullWithdraw = flag === 1;
  
  console.log(`[relayer] flag = ${flag}, isFullWithdraw = ${isFullWithdraw}, off after flag = ${off}`);

  // Output commitments (compressed format)
  const outputCommitments = [];
  if (!isFullWithdraw) {
    const nonZeroCount = take(1)[0];
    console.log(`[relayer] Reading ${nonZeroCount} non-zero output commitments (compressed)...`);
    
    for (let i = 0; i < N_OUTS; i++) {
      outputCommitments.push(Buffer.alloc(32));
    }
    
    for (let j = 0; j < nonZeroCount; j++) {
      const idx = take(1)[0];
      const commitment = take(32);
      console.log(`[relayer]   outputCommitments[${idx}] = ${commitment.toString('hex').slice(0, 16)}...`);
      outputCommitments[idx] = commitment;
    }
  } else {
    console.log(`[relayer] Full withdraw - filling with zero commitments`);
    for (let i = 0; i < N_OUTS; i++) {
      outputCommitments.push(Buffer.alloc(32));
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
    isFullWithdraw,
    inputNullifiers,
    outputCommitments,
  };
}

function recipientLimbsLE(pk) {
  const b = pk.toBytes(); // 32 bytes
  const out = [];
  for (let i = 0; i < 4; i++) {
    let limb = 0n;
    for (let j = 0; j < 8; j++) {
      limb |= BigInt(b[i * 8 + j]) << (8n * BigInt(j));
    }
    out.push(limb);
  }
  return out;
}

function asLE32HexFromDecimalString(nStr) {
  let x = BigInt(nStr);
  const b = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return "0x" + b.toString("hex");
}

/**
 * Off-chain verifier for the OLD single-note circuit
 */
async function verifyOffchainSingle(memo) {
  const p = parsePackedSingle(memo);

  const destLimbs = recipientLimbsLE(p.recipient);

  const pubs = [
    ...destLimbs,
    BigInt(p.nonce),
    be32ToBig(p.newCommitment),
    BigInt(p.publicAmount),
    be32ToBig(p.noteNullifier),
  ].map(String);

  const labels = ["D0", "D1", "D2", "D3", "NON", "NEWC", "AMT", "NN"];
  for (let i = 0; i < pubs.length; i++) {
    console.log(
      `[verifyOffchain-single] pub[${i} ${labels[i]}] = ${pubs[i]} (${asLE32HexFromDecimalString(
        pubs[i]
      )})`
    );
  }

  // reconstruct Groth16 proof
  const ax = be32ToBig(p.A.subarray(0, 32)).toString();
  const ay = be32ToBig(p.A.subarray(32, 64)).toString();
  const cx = be32ToBig(p.C.subarray(0, 32)).toString();
  const cy = be32ToBig(p.C.subarray(32, 64)).toString();

  const x0 = be32ToBig(p.B.subarray(0, 32)).toString();
  const x1 = be32ToBig(p.B.subarray(32, 64)).toString();
  const y1 = be32ToBig(p.B.subarray(64, 96)).toString();
  const y0 = be32ToBig(p.B.subarray(96, 128)).toString();

  const proof = {
    protocol: "groth16",
    curve: "bn128",
    pi_a: [ax, ay],
    pi_b: [
      [x0, x1],
      [y0, y1],
    ],
    pi_c: [cx, cy],
  };

  const ok = await snarkjs.groth16.verify(vkJson, pubs, proof);
  if (!ok) throw new Error("offchain proof verify failed (single-note)");

  return p;
}

async function verifyOffchainJoinSplit(memo) {
  console.warn(
    "[relayer] VERIFY_OFFCHAIN is enabled, but join-split off-chain verification is not implemented; skipping."
  );
  return parsePackedJoinSplitFull(memo);
}

function ixPrepareWithdrawViaMemoSingle(
  programId,
  { state, pool, recipient, relayer, escrow, preparedPda, nullifierPda, notePdas },
  memoBytes
) {
  const disc = anchorIxDisc("prepare_withdraw_via_memo");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(memoBytes.length, 0);
  const data = Buffer.concat([disc, len, memoBytes]);

  const keys = [
    { pubkey: state, isSigner: false, isWritable: true },
    { pubkey: pool, isSigner: false, isWritable: false },
    { pubkey: recipient, isSigner: false, isWritable: true },
    { pubkey: relayer, isSigner: true, isWritable: false },
    { pubkey: escrow, isSigner: false, isWritable: true },
    { pubkey: preparedPda, isSigner: false, isWritable: true },
    { pubkey: nullifierPda, isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];

  for (const p of notePdas) {
    keys.push({ pubkey: p, isSigner: false, isWritable: true });
  }

  return new TransactionInstruction({ programId, keys, data });
}

function ixPrepareWithdrawViaMemoJoinSplit(
  programId,
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
  },
  memoBytes
) {

  const disc = anchorIxDisc("prepare_withdraw_via_memo");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(memoBytes.length, 0);

  const data = Buffer.concat([disc, len, memoBytes]);

  const keys = [
    { pubkey: state,        isSigner: false, isWritable: true  }, // 0
    { pubkey: pool,         isSigner: false, isWritable: true  }, // 1
    { pubkey: recipient,    isSigner: false, isWritable: true  }, // 2
    { pubkey: relayer,      isSigner: false, isWritable: false }, // 3
    { pubkey: escrow,       isSigner: false, isWritable: true  }, // 4
    { pubkey: preparedPda,  isSigner: false, isWritable: true  }, // 5
    { pubkey: signer,       isSigner: true,  isWritable: true  }, // 6
    { pubkey: SystemProgram.programId, isSigner:false, isWritable:false },
  ];

  for (const nf of nullifierPdas) {
    keys.push({ pubkey: nf, isSigner: false, isWritable: true });
  }
  for (const notePda of (outputNotePdas || [])) {
    keys.push({ pubkey: notePda, isSigner: false, isWritable: true });
  }

  return new TransactionInstruction({ programId, keys, data });
}

function ixExecutePrepared(
  programId,
  { state, pool, recipient, relayer, escrow, preparedPda }
) {
  const disc = anchorIxDisc("execute_prepared_withdraw");
  const keys = [
    { pubkey: state, isSigner: false, isWritable: true },
    { pubkey: pool, isSigner: false, isWritable: true },
    { pubkey: recipient, isSigner: false, isWritable: true },
    { pubkey: relayer, isSigner: true, isWritable: true },
    { pubkey: escrow, isSigner: false, isWritable: true },
    { pubkey: preparedPda, isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];
  return new TransactionInstruction({ programId, keys, data: disc });
}

async function sendTxWithLogs(conn, tx, signers) {
  try {
    const sig = await conn.sendTransaction(tx, signers, {
      skipPreflight: false,
    });
    await conn.confirmTransaction(sig, "confirmed");
    return { signature: sig, logs: null };
  } catch (e) {
    try {
      const sim = await conn.simulateTransaction(tx, signers);
      const logs = sim?.value?.logs || null;
      throw new Error(
        `SendTransactionError: ${e.message}\nLogs:\n${JSON.stringify(
          logs,
          null,
          2
        )}`
      );
    } catch {
      throw new Error(`SendTransactionError: ${e.message}`);
    }
  }
}

async function handleWithdrawViaMemoSingle(
  req,
  { conn, RELAYER, CU_LIMIT_PREPARE, CU_LIMIT_EXECUTE, CU_PRICE_MICROLAMPORTS }
) {
  const programId = new PublicKey(req.programId);
  const state = pdaState(programId);
  const pool = pdaPool(programId);
  const escrow = pdaEscrow(programId);
  const recipient = new PublicKey(req.recipient);
  const memo = Buffer.from(req.memoPackedBase64, "base64");

  let parsed;
  if (VERIFY_OFFCHAIN) {
    parsed = await verifyOffchainSingle(memo);
    log({
      t: now(),
      level: "info",
      phase: "verify-single",
      ok: true,
      nonce: parsed.nonce.toString(),
      recipient: recipient.toBase58(),
      publicAmount: parsed.publicAmount.toString(),
    });
  } else {
    parsed = parsePackedSingle(memo);
  }

  const prepared = pdaPreparedSingle(programId, parsed.nonce);
  const nullifier = pdaNullifier(programId, parsed.noteNullifier);
  const notePdas = (parsed.changes || []).map((ch) =>
    pdaNote(programId, ch.commitment)
  );

  {
    const tx = new Transaction();
    tx.add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT_PREPARE })
    );
    if (CU_PRICE_MICROLAMPORTS > 0) {
      tx.add(
        ComputeBudgetProgram.setComputeUnitPrice({
          microLamports: CU_PRICE_MICROLAMPORTS,
        })
      );
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
    );

    tx.feePayer = RELAYER.publicKey;
    tx.recentBlockhash = (await conn.getLatestBlockhash()).blockhash;

    const { signature } = await sendTxWithLogs(conn, tx, [RELAYER]);
    log({ t: now(), level: "info", phase: "prepare-single", sig: signature });
  }

  {
    const tx2 = new Transaction();
    tx2.add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT_EXECUTE })
    );
    if (CU_PRICE_MICROLAMPORTS > 0) {
      tx2.add(
        ComputeBudgetProgram.setComputeUnitPrice({
          microLamports: CU_PRICE_MICROLAMPORTS,
        })
      );
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
    );

    tx2.feePayer = RELAYER.publicKey;
    tx2.recentBlockhash = (await conn.getLatestBlockhash()).blockhash;

    const { signature } = await sendTxWithLogs(conn, tx2, [RELAYER]);
    log({ t: now(), level: "info", phase: "execute-single", sig: signature });
    return { sig: signature };
  }
}

async function handleWithdrawViaMemoJoinSplit(
  req,
  { conn, RELAYER, CU_LIMIT_PREPARE, CU_LIMIT_EXECUTE, CU_PRICE_MICROLAMPORTS }
) {
  const programId = new PublicKey(req.programId);
  const state = pdaState(programId);
  const pool = pdaPool(programId);
  const escrow = pdaEscrow(programId);
  const recipient = new PublicKey(req.recipient);  // ← from request
  const memo = Buffer.from(req.memoPackedBase64, "base64");

  const parsed = await verifyOffchainJoinSplit(memo);

  console.log(`[relayer] publicAmount: ${parsed.publicAmount}`);
  console.log(`[relayer] nInputs: ${parsed.nInputs}`);
  console.log(`[relayer] isFullWithdraw: ${parsed.isFullWithdraw}`);
  console.error(`[relayer] DEBUG CHECKPOINT 1`);

  const prepared = pdaPreparedJoinSplit(programId, parsed.nonce);
  console.error(`[relayer] DEBUG CHECKPOINT 2`);

  const nullifierPdas = parsed.inputNullifiers
    .slice(0, parsed.nInputs)
    .map((n) => pdaNullifier(programId, n));
  console.error(`[relayer] DEBUG CHECKPOINT 3`);

  // Get current next_index from state to calculate output note indices
  const stateInfo = await conn.getAccountInfo(state);
  if (!stateInfo) throw new Error("State account not found");
  // Offset: discriminator(8) + admin(32) + bump(1) + escrow_bump(1) + pool_bump(1) = 43
  const nextIndex = stateInfo.data.readUInt32LE(43);
  console.error(`[relayer] DEBUG CHECKPOINT 4: nextIndex=${nextIndex}`);
  
  console.log(`[relayer] Current next_index: ${nextIndex}`);
  
  // Create PDAs for non-zero output commitments
  const outputNotePdas = [];
  for (let j = 0; j < parsed.outputCommitments.length; j++) {
    const commitment = parsed.outputCommitments[j];
    // Check if commitment is all zeros
    const isZero = commitment.every(b => b === 0);
    if (!isZero) {
      const treeIdx = nextIndex + outputNotePdas.length;
      const notePda = pdaNoteByIndex(programId, treeIdx);
      outputNotePdas.push(notePda);
      console.log(`[relayer] Output ${j}: index=${treeIdx}, PDA=${notePda.toBase58()}`);
    }
  }
  
  console.log(`[relayer] Total output note PDAs: ${outputNotePdas.length}`);

  {
    const preparedLen = 8 + 1 + 1 + 8 + 32 + 32 + 8 + 8;
    const nullifierLen = 8 + 1;
    const noteLen = 8 + 1 + 4 + 32 + 32 + 8 + 4;
    
    const rentPrepared = await conn.getMinimumBalanceForRentExemption(preparedLen);
    const rentNullifier = await conn.getMinimumBalanceForRentExemption(nullifierLen);
    const rentNote = await conn.getMinimumBalanceForRentExemption(noteLen);
    
    const safety = 3000000;
    const mustHave = rentPrepared + (rentNullifier * parsed.nInputs) + (rentNote * outputNotePdas.length) + safety + Number(parsed.publicAmount);
    
    const escrowInfo = await conn.getAccountInfo(escrow);
    const current = escrowInfo?.lamports ?? 0;
    
    if (current < mustHave) {
      const need = mustHave - current;
      log({
        t: now(),
        level: "info",
        phase: "fund-escrow",
        current,
        mustHave,
        need,
      });
      
      const fundTx = new Transaction().add(
        SystemProgram.transfer({
          fromPubkey: RELAYER.publicKey,
          toPubkey: escrow,
          lamports: need,
        })
      );
      
      fundTx.feePayer = RELAYER.publicKey;
      fundTx.recentBlockhash = (await conn.getLatestBlockhash()).blockhash;
      
      const fundSig = await conn.sendTransaction(fundTx, [RELAYER]);
      await conn.confirmTransaction(fundSig, "confirmed");
      
      log({
        t: now(),
        level: "info",
        phase: "fund-escrow-done",
        sig: fundSig,
        amount: need,
      });
    }
  }

  {
    const tx = new Transaction();
    tx.add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT_PREPARE })
    );
    if (CU_PRICE_MICROLAMPORTS > 0) {
      tx.add(
        ComputeBudgetProgram.setComputeUnitPrice({
          microLamports: CU_PRICE_MICROLAMPORTS,
        })
      );
    }

    console.log(`[relayer] About to build ix with ${outputNotePdas.length} output PDAs`);
    if (outputNotePdas.length > 0) {
      console.log(`[relayer] First output PDA: ${outputNotePdas[0].toBase58()}`);
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
    );

    tx.feePayer = RELAYER.publicKey;
    tx.recentBlockhash = (await conn.getLatestBlockhash()).blockhash;

    const { signature } = await sendTxWithLogs(conn, tx, [RELAYER]);
    log({
      t: now(),
      level: "info",
      phase: "prepare-join-split",
      sig: signature,
    });
  }

  {
    const tx2 = new Transaction();
    tx2.add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: CU_LIMIT_EXECUTE })
    );
    if (CU_PRICE_MICROLAMPORTS > 0) {
      tx2.add(
        ComputeBudgetProgram.setComputeUnitPrice({
          microLamports: CU_PRICE_MICROLAMPORTS,
        })
      );
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
    );

    tx2.feePayer = RELAYER.publicKey;
    tx2.recentBlockhash = (await conn.getLatestBlockhash()).blockhash;

    const { signature } = await sendTxWithLogs(conn, tx2, [RELAYER]);
    log({
      t: now(),
      level: "info",
      phase: "execute-join-split",
      sig: signature,
    });
    return { sig: signature };
  }
}

(async () => {
  if (VERIFY_OFFCHAIN) {
    snarkjs = require("snarkjs");
    const fs = require("fs");
    if (!process.env.VK_JSON) {
      throw new Error(
        "VERIFY_OFFCHAIN=true but VK_JSON not set (expected e.g. tests/circuits/privw_vk.json)"
      );
    }
    vkJson = JSON.parse(fs.readFileSync(process.env.VK_JSON, "utf8"));
  }

  const RELAYER = Keypair.fromSecretKey(
    bs58.decode(mustEnv("RELAYER_SECRET_BASE58"))
  );
  const RPC = process.env.RPC || "https://api.devnet.solana.com";
  const BIND = process.env.BIND || "127.0.0.1";
  const PORT = parseInt(process.env.PORT || "8787", 10);

  const CU_LIMIT_PREPARE = parseInt(
    process.env.CU_LIMIT_PREPARE || "1300000",
    10
  );
  const CU_LIMIT_EXECUTE = parseInt(
    process.env.CU_LIMIT_EXECUTE || "1300000",
    10
  );
  const CU_PRICE_MICROLAMPORTS = parseInt(
    process.env.CU_PRICE_MICROLAMPORTS || "0",
    10
  );

  const conn = new Connection(RPC, "confirmed");
  log({
    t: now(),
    level: "info",
    phase: "boot",
    relayer: RELAYER.publicKey.toBase58(),
    rpc: RPC,
    ws: `ws://${BIND}:${PORT}`,
    verifyOffchain: VERIFY_OFFCHAIN,
    cuLimitPrepare: CU_LIMIT_PREPARE,
    cuLimitExecute: CU_LIMIT_EXECUTE,
    cuPriceMicrolamports: CU_PRICE_MICROLAMPORTS,
  });

  const wss = new WebSocket.Server({ host: BIND, port: PORT });

  wss.on("connection", (ws) => {
    ws.on("message", async (raw) => {
      let req;
      try {
        req = JSON.parse(raw.toString());
      } catch {
        return;
      }
      const id = req.id || crypto.randomUUID();
      const reply = (ok, payload) =>
        ws.send(
          JSON.stringify(
            ok
              ? { id, ok: true, ...payload }
              : {
                  id,
                  ok: false,
                  error: String(payload.error || payload),
                  logs: payload.logs,
                }
          )
        );

      try {
        if (req.type === "withdraw_via_memo") {
          const { sig } = await handleWithdrawViaMemoSingle(req, {
            conn,
            RELAYER,
            CU_LIMIT_PREPARE,
            CU_LIMIT_EXECUTE,
            CU_PRICE_MICROLAMPORTS,
          });
          log({
            t: now(),
            level: "info",
            phase: "broadcast-single",
            sig,
            recipient: req.recipient,
          });
          return reply(true, { signature: sig });
        }

        if (req.type === "withdraw_via_memo_join_split") {
          const { sig } = await handleWithdrawViaMemoJoinSplit(req, {
            conn,
            RELAYER,
            CU_LIMIT_PREPARE,
            CU_LIMIT_EXECUTE,
            CU_PRICE_MICROLAMPORTS,
          });
          log({
            t: now(),
            level: "info",
            phase: "broadcast-join-split",
            sig,
            recipient: req.recipient,
          });
          return reply(true, { signature: sig });
        }

        return reply(false, "unknown type");
      } catch (e) {
        const msg = String(e?.message || e);
        log({ t: now(), level: "error", phase: "broadcast", err: msg });
        const logsMatch = /Logs:\n([\s\S]*)$/.exec(msg);
        const logs = logsMatch ? logsMatch[1] : undefined;
        return reply(false, { error: msg, logs });
      }
    });
  });
})();
