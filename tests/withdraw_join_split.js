#!/usr/bin/env node

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bs58 = require("bs58");
const nacl = require("tweetnacl");
const { groth16 } = require("snarkjs");
const WebSocket = require("ws");
const createBlakeHash = require("blake-hash");
require("dotenv").config();

const {
  Connection,
  PublicKey,
  Keypair,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} = require("@solana/web3.js");

const N_INS = 6; 
const N_OUTS = 6;
const TREE_DEPTH = 26;

const TWO64 = 1n << 64n;
const TWO128 = 1n << 128n;
const TWO192 = 1n << 192n;

const P_FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function toFr(x) {
  let v = BigInt(x);
  v %= P_FR;
  if (v < 0n) v += P_FR;
  return v;
}

const frStr = (x) => toFr(x).toString();

const WASM = must(
  arg("wasm", getEnv("WASM_PATH", null)),
  "WASM path required (pass --wasm or set WASM_PATH)"
);

const ZKEY = must(
  arg("zkey", getEnv("ZKEY_PATH", null)),
  "ZKEY path required (pass --zkey or set ZKEY_PATH)"
);

console.log("[DEBUG] WASM PATH:", WASM);
console.log("[DEBUG] ZKEY PATH:", ZKEY);

function must(v, msg) {
  if (!v) throw new Error(msg);
  return v;
}

function getEnv(key, def) {
  return process.env[key] ?? def;
}

function arg(key, def) {
  const idx = process.argv.indexOf("--" + key);
  const hasVal =
    idx > -1 &&
    process.argv[idx + 1] &&
    !process.argv[idx + 1].startsWith("--");

  return hasVal ? process.argv[idx + 1] : getEnv(key.toUpperCase(), def);
}

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest();

function beOrLe32FromBig(xIn, little = true) {
  let x = BigInt(xIn);
  const out = Buffer.alloc(32);

  if (little) {
    for (let i = 0; i < 32; i++) {
      out[i] = Number(x & 0xffn);
      x >>= 8n;
    }
  } else {
    for (let i = 31; i >= 0; i--) {
      out[i] = Number(x & 0xffn);
      x >>= 8n;
    }
  }
  return out;
}

function u32leToBig(buf) {
  let x = 0n;
  for (let i = 0; i < 32; i++) {
    x |= BigInt(buf[i] || 0) << (8n * BigInt(i));
  }
  return x;
}

function frTo32(x, be = true) {
  let bi;

  if (typeof x === "bigint") bi = x;
  else if (typeof x === "number") bi = BigInt(x);
  else if (typeof x === "string") {
    const s = x.trim();
    bi = s.startsWith("0x") ? BigInt(s) : BigInt(s);
  } else {
    throw new Error("frTo32: unsupported type");
  }

  if (bi < 0n) throw new Error("frTo32: negative value");

  let hex = bi.toString(16);
  if (hex.length % 2) hex = "0" + hex;

  const raw = Buffer.from(hex, "hex");
  if (raw.length > 32) throw new Error("frTo32: value > 32 bytes");

  const out = Buffer.alloc(32, 0);

  if (be) {
    raw.copy(out, 32 - raw.length);
  } else {
    for (let i = 0; i < raw.length; i++) {
      out[i] = raw[raw.length - 1 - i];
    }
  }
  return out;
}

function u64le(n) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(BigInt(n));
  return buf;
}

function normHex(h) {
  const s = String(h).trim().toLowerCase();
  return s.startsWith("0x") ? s : "0x" + s;
}

function frFrom32be(buf) {
  let x = 0n;
  for (let i = 0; i < 32; i++) {
    x = (x << 8n) | BigInt(buf[i]);
  }
  return x;
}

function clusterTagFromRpc(url) {
  if (/devnet/i.test(url)) return "devnet";
  if (/testnet/i.test(url)) return "testnet";
  return "mainnet";
}

function scopedLedgerPath(programId, rpcUrl) {
  const cluster = clusterTagFromRpc(rpcUrl || "");
  const base = `wallet_ledger.${programId}.${cluster}.json`;
  return path.resolve(base);
}

function readLedgerSafeScoped(programId, rpcUrl) {
  const ledgerPath = scopedLedgerPath(programId, rpcUrl);
  try {
    const j = JSON.parse(fs.readFileSync(ledgerPath, "utf8"));
    j.notes = Array.isArray(j.notes) ? j.notes : [];
    return j;
  } catch (_) {
    return { notes: [] };
  }
}

function writeLedger(programId, rpcUrl, ledger) {
  const ledgerPath = scopedLedgerPath(programId, rpcUrl);
  fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2));
  return ledgerPath;
}

function markNotesSpent(programId, rpcUrl, memoFiles) {
  const ledger = readLedgerSafeScoped(programId, rpcUrl);

  for (const file of memoFiles) {
    const idx = (ledger.notes || []).findIndex(
      (n) => n.memoFile === file && !n.spent
    );
    if (idx >= 0) {
      ledger.notes[idx].spent = true;
    }
  }

  const ledgerPath = writeLedger(programId, rpcUrl, ledger);
  const cluster = clusterTagFromRpc(rpcUrl);
  const totalUnspent = (ledger.notes || [])
    .filter(n => !n.spent && n.balance > 0)
    .reduce((acc, n) => acc + BigInt(n.balance), 0n);
  
  console.log(
    `[ledger] Updated → ${ledgerPath} (total unspent: ${totalUnspent})`
  );
}

async function saveChangeNote(programId, rpcUrl, changeNoteData) {
  const cluster = clusterTagFromRpc(rpcUrl);
  const ledger = readLedgerSafeScoped(programId, rpcUrl);

  // Generate encrypted memo for the change note
  const memoPath = `change_note_${changeNoteData.withdrawalSig}.bin`;
  const encryptedMemo = await changeNoteData.encryptedMemo;
  fs.writeFileSync(memoPath, encryptedMemo);
  console.log(`[ledger] 💾 Saved change note memo: ${memoPath}`);

  // Save change note receipt file for reference
  const receiptPath = `change_note_${changeNoteData.withdrawalSig}.json`;
  const receipt = {
    type: "change",
    withdrawal_signature: changeNoteData.withdrawalSig,
    balance_lamports: changeNoteData.balance.toString(),
    note_nonce: changeNoteData.noteNonce.toString(),
    commitment_hex: changeNoteData.commitmentHex,
    memo_file: memoPath,
    created_at: new Date().toISOString(),
    program_id: programId,
    cluster,
  };
  fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));
  console.log(`[ledger] 💾 Saved change note receipt: ${receiptPath}`);

  // Add to ledger with memo file reference
  ledger.notes = ledger.notes || [];
  ledger.notes.push({
    memoFile: memoPath,
    spent: false,
    balance: Number(changeNoteData.balance),
    noteNonce: changeNoteData.noteNonce.toString(),
    commitment: changeNoteData.commitmentHex,
    treeIndex: null, // Will be assigned when scanned from chain
    type: "change",
    withdrawalSig: changeNoteData.withdrawalSig,
    createdAt: new Date().toISOString(),
  });

  const ledgerPath = writeLedger(programId, rpcUrl, ledger);
  const totalUnspent = (ledger.notes || [])
    .filter(n => !n.spent && n.balance > 0)
    .reduce((acc, n) => acc + BigInt(n.balance), 0n);
  
  console.log(
    `[ledger] ✅ Change note added to ledger (total unspent: ${totalUnspent})`
  );

  return memoPath;
}

/* ------------------------------------------------------------------------- */
/*                              program + PDAs                               */
/* ------------------------------------------------------------------------- */

const PROGRAM_ID_RAW = must(getEnv("PROGRAM_ID"), "PROGRAM_ID required");
const PROGRAM = new PublicKey(PROGRAM_ID_RAW);

const pdaState = () =>
  PublicKey.findProgramAddressSync([Buffer.from("state")], PROGRAM)[0];

const pdaPool = () =>
  PublicKey.findProgramAddressSync([Buffer.from("pool")], PROGRAM)[0];

const pdaEscrow = () =>
  PublicKey.findProgramAddressSync([Buffer.from("escrow")], PROGRAM)[0];

async function readStateHeader(conn, statePk) {
  const ai = await conn.getAccountInfo(statePk);
  if (!ai) throw new Error("state not initialized");

  const data = ai.data;

  const offNextIndex = 8 + 32 + 1 + 1 + 1;
  const nextIndex = data.readUInt32LE(offNextIndex);

  const offRoot = offNextIndex + 4;
  const currentRoot = Buffer.from(data.subarray(offRoot, offRoot + 32));

  const offRootHistoryIdx = offRoot + 32;
  let off = offRootHistoryIdx + 1;

  const zeroesLen = data.readUInt32LE(off);
  off += 4;

  const zeroesBytes = data.subarray(off, off + zeroesLen);
  if (zeroesLen < 32) {
    throw new Error("GlobalState.zeroes too short");
  }

  const zeroLeaf = Buffer.from(zeroesBytes.subarray(0, 32));

  return {
    nextIndex,
    currentRoot,
    zeroLeaf,
    raw: data,
  };
}

let CIRCOM = null;

async function loadCircomRaw() {
  let lib = null;

  try {
    lib = require("circomlibjs-pure");
  } catch (_) {}

  if (!lib) {
    try {
      lib = require("circomlibjs");
    } catch (_) {}
  }

  if (!lib) throw new Error("Install circomlibjs or circomlibjs-pure");

  const buildBJ = lib.buildBabyjub || lib.buildBabyJub;
  const BJ =
    lib.babyJub ||
    lib.babyjub ||
    (typeof buildBJ === "function" ? await buildBJ() : null);

  const Poseidon =
    lib.poseidon ||
    (typeof lib.buildPoseidon === "function"
      ? await lib.buildPoseidon()
      : null);

  if (!BJ || !Poseidon) {
    throw new Error("Failed to load babyJub/poseidon");
  }

  return { BJ, Poseidon };
}

async function getCircom() {
  if (!CIRCOM) {
    CIRCOM = await loadCircomRaw();
  }
  return CIRCOM;
}

async function deriveViewPrivFromSolanaSk(secretKey) {
  const { BJ } = await getCircom();
  const subOrder = BigInt(BJ.subOrder);

  let skHash =
    BigInt("0x" + sha256(secretKey).toString("hex")) % subOrder;
  if (skHash === 0n) skHash = 1n;

  return skHash;
}

async function buildChangeNoteMemo(viewPub, balance, noteNonce, ownerPubkey) {
  const { BJ } = await getCircom();
  const subOrder = BigInt(BJ.subOrder);
  
  let ephSk = BigInt("0x" + crypto.randomBytes(32).toString("hex")) % subOrder;
  if (ephSk === 0n) ephSk = 1n;
  
  const ephPub = BJ.mulPointEscalar(BJ.Base8, ephSk);
  const eX = BigInt(BJ.F.toObject(ephPub[0]));
  const eY = BigInt(BJ.F.toObject(ephPub[1]));
  
  const shared = BJ.mulPointEscalar([BJ.F.e(viewPub[0]), BJ.F.e(viewPub[1])], ephSk);
  const sX = BigInt(BJ.F.toObject(shared[0]));
  const sY = BigInt(BJ.F.toObject(shared[1]));
  
  const key = sha256(Buffer.concat([
    Buffer.from("privw:v1"),
    beOrLe32FromBig(sX, true),
    beOrLe32FromBig(sY, true)
  ]));
  
  const nonce = crypto.randomBytes(24);
  
  if (!(ownerPubkey instanceof PublicKey)) {
    throw new Error("ownerPubkey must be a PublicKey");
  }
  const ownerBytes = Buffer.from(ownerPubkey.toBytes());
  
  const payload = Buffer.concat([
    beOrLe32FromBig(balance, true),
    beOrLe32FromBig(noteNonce, true),
    ownerBytes
  ]);
  
  const box = nacl.secretbox(
    new Uint8Array(payload),
    new Uint8Array(nonce),
    new Uint8Array(key)
  );
  
  return Buffer.concat([
    Buffer.from("PWV1"),
    beOrLe32FromBig(eX, true),
    beOrLe32FromBig(eY, true),
    Buffer.from(nonce),
    Buffer.from(box)
  ]);
}

async function openMemo(memo, viewPriv) {
  const { BJ } = await getCircom();

  if (memo.length < 4 + 32 + 32 + 24 + 16) {
    throw new Error("memo too short");
  }
  if (memo.subarray(0, 4).toString("utf8") !== "PWV1") {
    throw new Error("bad memo tag");
  }

  const eX = u32leToBig(memo.subarray(4, 36));
  const eY = u32leToBig(memo.subarray(36, 68));
  const nonce = memo.subarray(68, 92);
  const box = memo.subarray(92);

  const shared = BJ.mulPointEscalar(
    [BJ.F.e(eX), BJ.F.e(eY)],
    viewPriv
  );

  const sX = BigInt(BJ.F.toObject(shared[0]));
  const sY = BigInt(BJ.F.toObject(shared[1]));

  const key = sha256(
    Buffer.concat([
      Buffer.from("privw:v1"),
      beOrLe32FromBig(sX, true),
      beOrLe32FromBig(sY, true),
    ])
  );

  const opened = nacl.secretbox.open(
    new Uint8Array(box),
    new Uint8Array(nonce),
    new Uint8Array(key)
  );
  if (!opened) throw new Error("ciphertext auth failed");

  const buf = Buffer.from(opened);

  const balance = u32leToBig(buf.subarray(0, 32));
  const noteNonce = u32leToBig(buf.subarray(32, 64));
  const ownerPk = new PublicKey(buf.subarray(64, 96));

  return { balance, noteNonce, ownerPk };
}

function limbsFromPubkey(pkBase58) {
  const b = new PublicKey(pkBase58).toBytes();
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

async function ensureEscrowHasForWithdraw(
  connection,
  maybePayer,
  escrowPk,
  needsChangeNote
) {
  const preparedLen = 8 + 1 + 1 + 8 + 32 + 32 + 8 + 8;
  const noteLen = needsChangeNote
    ? 8 + 1 + 4 + 32 + 4 + needsChangeNote
    : 0;
  const nullifierLen = 8 + 1;

  const rentPrepared =
    await connection.getMinimumBalanceForRentExemption(preparedLen);
  const rentNote = noteLen
    ? await connection.getMinimumBalanceForRentExemption(noteLen)
    : 0;
  const rentNullifier =
    await connection.getMinimumBalanceForRentExemption(nullifierLen);

  const safety = Number(getEnv("ESCROW_SAFETY", "3000000"));

  const mustHave = rentPrepared + rentNote + rentNullifier + safety;

  const ai = await connection.getAccountInfo(escrowPk);
  const current = ai?.lamports ?? 0;

  if (current >= mustHave) return;

  if (!maybePayer) {
    console.warn(
      `[escrow] Needs top-up: have ${current}, need ≥ ${mustHave}. Skipping (no PRIVATE_KEY).`
    );
    return;
  }

  const need = mustHave - current;

  const tx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: maybePayer.publicKey,
      toPubkey: escrowPk,
      lamports: need,
    })
  );

  const sig = await sendAndConfirmTransaction(connection, tx, [
    maybePayer,
  ]);
  console.log(
    `[escrow] Topped up ESCROW by ${need} lamports. Sig: ${sig}`
  );
}

function packProofSnarkjs(proof) {
  const a = Buffer.concat([
    frTo32(proof.pi_a[0], true),
    frTo32(proof.pi_a[1], true),
  ]);

  const b = Buffer.concat([
    frTo32(proof.pi_b[0][0], true),
    frTo32(proof.pi_b[0][1], true),
    frTo32(proof.pi_b[1][0], true),
    frTo32(proof.pi_b[1][1], true),
  ]);

  const c = Buffer.concat([
    frTo32(proof.pi_c[0], true),
    frTo32(proof.pi_c[1], true),
  ]);

  return { a, b, c };
}

function buildJoinSplitMemoPacked({
  proof,
  publicAmount,
  extAmountIn,
  nonce,
  nInputs,
  inputNullifier,
  outputCommitment,
  isFullWithdraw,
}) {
  const { a, b, c } = packProofSnarkjs(proof);
  const parts = [];

  parts.push(a, b, c);

  parts.push(u64le(BigInt(publicAmount)));
  parts.push(u64le(BigInt(extAmountIn)));
  parts.push(u64le(BigInt(nonce)));

  const nInputsBuf = Buffer.alloc(4);
  nInputsBuf.writeUInt32LE(nInputs, 0);
  parts.push(nInputsBuf);

  for (let i = 0; i < N_INS; i++) {
    parts.push(frTo32(inputNullifier[i], true));
  }

  const flag = Buffer.from([isFullWithdraw ? 1 : 0]);
  parts.push(flag);

  if (!isFullWithdraw) {
    let nonZeroCount = 0;
    const zeroCommit = "14744269619966411208579211824598458697587494354926760081771325075741142829156";
    
    for (let j = 0; j < N_OUTS; j++) {
      if (outputCommitment[j].toString() !== zeroCommit && outputCommitment[j] !== 0n) {
        nonZeroCount++;
      }
    }
    
    parts.push(Buffer.from([nonZeroCount]));
    
    for (let j = 0; j < N_OUTS; j++) {
      if (outputCommitment[j].toString() !== zeroCommit && outputCommitment[j] !== 0n) {
        parts.push(Buffer.from([j]));
        parts.push(frTo32(outputCommitment[j], true));
      }
    }
    
    console.log(`[memo] Compressed: ${nonZeroCount} non-zero outputs (saved ${(N_OUTS - nonZeroCount) * 32} bytes)`);
  }

  return Buffer.concat(parts);
}

function noteRecordDiscriminator() {
  return sha256(Buffer.from("account:NoteRecord")).subarray(0, 8);
}

async function fetchAllNoteRecords(conn) {
  const disc = noteRecordDiscriminator();

  const accounts = await conn.getProgramAccounts(PROGRAM, {
    filters: [
      {
        memcmp: {
          offset: 0,
          bytes: bs58.encode(disc),
        },
      },
    ],
  });

  return accounts.map(({ pubkey, account }) => {
    const data = account.data;
    if (data.length < 49) {
      throw new Error(
        `NoteRecord too small at ${pubkey.toBase58()}`
      );
    }

    const bump = data[8];
    const index = data.readUInt32LE(9);
    const commitment = Buffer.from(data.subarray(13, 45));
    const ctLen = data.readUInt32LE(45);
    const ciphertext = Buffer.from(data.subarray(49, 49 + ctLen));

    return {
      pubkey,
      bump,
      index,
      commitment,
      ciphertext,
    };
  });
}

function toBig(x) {
  if (typeof x === "bigint") return x;
  if (typeof x === "number") return BigInt(x);
  return BigInt(x.toString());
}

function buildPoseidonFn(Poseidon) {
  return (inputs) => {
    const inFr = inputs.map((x) => toFr(x));
    const out = Poseidon(inFr);
    return toFr(toBig(out));
  };
}

function poseidonHash2Bytes(poseidonFr, leftBytes, rightBytes) {
  const lx = frFrom32be(leftBytes);
  const rx = frFrom32be(rightBytes);
  const out = poseidonFr([lx, rx]);
  return frTo32(out, true);
}

function scalarMulCircuitStyle(BJ, point, scalar) {
  const nBits = 252;
  let k = BigInt(scalar);
  const bits = [];

  for (let i = 0; i < nBits; i++) {
    bits.push(k & 1n);
    k >>= 1n;
  }

  let acc = [BJ.F.e(0), BJ.F.e(1)];

  for (let i = 0; i < nBits; i++) {
    acc = BJ.addPoint(acc, acc);

    const bit = bits[nBits - 1 - i];
    if (bit === 1n) {
      acc = BJ.addPoint(acc, point);
    }
  }

  return acc;
}

function buildFullMerkleTreeFromLeaves(
  leaves,
  poseidonFr,
  zeroLeaf,
  nextIndex
) {
  const expectedLeaves = 1 << TREE_DEPTH;
  if (leaves.length !== expectedLeaves) {
    throw new Error(
      `leaves length must be 2^${TREE_DEPTH} (got ${leaves.length})`
    );
  }

  const levels = [];

  const zeros = new Array(TREE_DEPTH + 1);
  zeros[0] = Buffer.from(zeroLeaf);

  for (let lvl = 1; lvl <= TREE_DEPTH; lvl++) {
    zeros[lvl] = poseidonHash2Bytes(poseidonFr, zeros[lvl - 1], zeros[lvl - 1]);
  }

  const lvl0 = new Array(expectedLeaves);
  for (let i = 0; i < expectedLeaves; i++) {
    lvl0[i] = i < nextIndex ? leaves[i] : zeros[0];
  }

  levels[0] = lvl0;

  for (let lvl = 1; lvl <= TREE_DEPTH; lvl++) {
    const prev = levels[lvl - 1];
    const curLen = prev.length >>> 1;
    const cur = new Array(curLen);

    const zeroBelow = zeros[lvl - 1];
    const zeroHere = zeros[lvl];

    const segmentSize = 1 << lvl;

    for (let i = 0; i < curLen; i++) {
      const startLeaf = i * segmentSize;

      if (startLeaf >= nextIndex) {
        cur[i] = zeroHere;
        continue;
      }

      const left = prev[2 * i];
      const right = prev[2 * i + 1];

      if (left === zeroBelow && right === zeroBelow) {
        cur[i] = zeroHere;
      } else {
        cur[i] = poseidonHash2Bytes(poseidonFr, left, right);
      }
    }

    levels[lvl] = cur;
  }

  return {
    levels,
    root: levels[TREE_DEPTH][0],
  };
}

function computeMerklePath(levels, leafIndex) {
  let idx = leafIndex;
  const pathElements = [];
  const pathIndexBits = [];

  for (let lvl = 0; lvl < TREE_DEPTH; lvl++) {
    const isRight = (idx & 1) === 1;
    const siblingIdx = isRight ? idx - 1 : idx + 1;
    const siblingNode = levels[lvl][siblingIdx];

    pathElements.push("0x" + siblingNode.toString("hex"));
    pathIndexBits.push(isRight ? "1" : "0");

    idx >>= 1;
  }

  return {
    pathElements,
    pathIndexBits,
  };
}

(async () => {
  function pickRelayerWs() {
    const cliWs = arg("relayer-ws", null);
    const cliGeneric = arg("relayer", null);
    const envWs = getEnv("RELAYER_WS", null);
    const isWs = (s) => typeof s === "string" && /^wss?:\/\//i.test(s);

    if (isWs(cliWs)) return cliWs;
    if (isWs(envWs)) return envWs;
    if (isWs(cliGeneric)) return cliGeneric;

    return "ws://127.0.0.1:8787";
  }

  const RELAYER_WS = pickRelayerWs();
  const OUT_PATH = arg("out", "join_split_withdraw_memo.bin");
  const RPC_URL = arg("rpc", "https://api.devnet.solana.com");
  const WITHDRAW_ARG = arg("withdraw", null);

  const RECIPIENT = arg("recipient", null)
    ? new PublicKey(arg("recipient"))
    : null;

  console.log("[client] JOIN-SPLIT withdraw (multi-note)");
  console.log("[client] RPC_URL:", RPC_URL);
  console.log("[client] RELAYER_WS:", RELAYER_WS);
  console.log(
    "[ledger] file:",
    scopedLedgerPath(PROGRAM_ID_RAW, RPC_URL)
  );

  const conn = new Connection(RPC_URL, "confirmed");
  const statePk = pdaState();
  const escrow = pdaEscrow();

  let VIEW_PRIV;
  const vpArg = arg("view-priv", null);

  if (vpArg) {
    VIEW_PRIV = BigInt(vpArg);
  } else if (getEnv("VIEW_PRIV")) {
    VIEW_PRIV = BigInt(getEnv("VIEW_PRIV"));
  } else if (process.env.PRIVATE_KEY) {
    const t = String(process.env.PRIVATE_KEY).trim();
    const secret = t.startsWith("[")
      ? Uint8Array.from(JSON.parse(t))
      : bs58.decode(t);

    VIEW_PRIV = await deriveViewPrivFromSolanaSk(secret);
    console.log("[client] Derived VIEW_PRIV from PRIVATE_KEY.");
  } else {
    throw new Error(
      "VIEW_PRIV required (env/arg) or PRIVATE_KEY to derive."
    );
  }

  const recipientPk = must(RECIPIENT, "--recipient required");

  const ledger = readLedgerSafeScoped(PROGRAM_ID_RAW, RPC_URL);
  const cluster = clusterTagFromRpc(RPC_URL);

  const allUnspent = (ledger.notes || []).filter(
    (n) =>
      !n.spent &&
      n.memoFile &&
      n.balance > 0
  );

  if (allUnspent.length === 0) {
    throw new Error("No unspent notes in ledger.");
  }

  const selected = allUnspent.slice(-N_INS);

  console.log(
    `[client] Using ${selected.length} input notes (max ${N_INS}) from ledger.`
  );
  selected.forEach((n, i) =>
    console.log(
      `[${i}] ${n.memoFile} balance=${n.balance} commitment=${n.commitment}`
    )
  );

  const { BJ, Poseidon, Ed } = await getCircom();
  const poseidonFr = buildPoseidonFn(Poseidon);

  const inputs = [];
  let totalBalance = 0n;

  for (const n of selected) {
    const memoBuf = fs.readFileSync(n.memoFile);
    const { balance, noteNonce, ownerPk } = await openMemo(
      memoBuf,
      VIEW_PRIV
    );

    if (balance.toString() !== n.balance.toString()) {
      console.warn(
        `[warn] ledger balance mismatch for ${n.memoFile}: ledger=${n.balance} decrypted=${balance.toString()}`
      );
    }

    totalBalance += balance;

    inputs.push({
      memoFile: n.memoFile,
      balance,
      noteNonce,
      ownerPk,
      commitmentHex: normHex(n.commitment),
    });
  }

  const nInputs = inputs.length;
  
  if (nInputs < 1) {
    throw new Error(`Need at least 1 unspent note for withdrawal. Currently have ${nInputs}. Please make a deposit first.`);
  }
  if (nInputs > N_INS) {
    throw new Error(`Too many notes selected (${nInputs}). Circuit supports max ${N_INS} inputs.`);
  }

  console.log(
    "[client] Total shielded balance in these notes:",
    totalBalance.toString()
  );

  let WITHDRAW = WITHDRAW_ARG ? BigInt(WITHDRAW_ARG) : totalBalance;

  if (WITHDRAW <= 0n) {
    throw new Error("--withdraw must be > 0");
  }
  if (WITHDRAW > totalBalance) {
    throw new Error("--withdraw exceeds total selected balance");
  }

  const REMAIN = totalBalance - WITHDRAW;

  console.log(
    `[client] WITHDRAW=${WITHDRAW.toString()} REMAIN(after)=${REMAIN.toString()}`
  );

  const isFullWithdraw = (REMAIN === 0n);
  if (!isFullWithdraw) {
    console.log(`[client] ⚠️  PARTIAL WITHDRAWAL: Will create change note for ${REMAIN} lamports`);
  }

  const {
    nextIndex: nextIndexOnChain,
    currentRoot: onChainRootBytes,
    zeroLeaf,
  } = await readStateHeader(conn, statePk);

  console.log("[tree] On-chain next_index:", nextIndexOnChain);

  const noteRecords = await fetchAllNoteRecords(conn);
  console.log(
    "[tree] Found",
    noteRecords.length,
    "on-chain NoteRecord PDAs."
  );

  const indexByCommitHex = new Map();

  for (const nr of noteRecords) {
    const commitHex = "0x" + nr.commitment.toString("hex");
    indexByCommitHex.set(commitHex.toLowerCase(), nr.index);
  }

  for (const inp of inputs) {
    const idx = indexByCommitHex.get(inp.commitmentHex.toLowerCase());
    if (idx === undefined) {
      // For change notes without treeIndex, scan blockchain
      console.log(`[tree] ⚠️  Note ${inp.memoFile} not found in tree, scanning...`);
      
      // Check if this is a change note that needs scanning
      const ledger = readLedgerSafeScoped(PROGRAM_ID_RAW, RPC_URL);
      const noteEntry = ledger.notes.find(n => n.memoFile === inp.memoFile);
      
      if (noteEntry && noteEntry.type === "change" && noteEntry.treeIndex === null) {
        const foundIdx = indexByCommitHex.get(inp.commitmentHex.toLowerCase());
        if (foundIdx !== undefined) {
          noteEntry.treeIndex = foundIdx;
          writeLedger(PROGRAM_ID_RAW, RPC_URL, ledger);
          console.log(`[tree] ✅ Found change note at tree index ${foundIdx}, ledger updated`);
          inp.treeIndex = foundIdx;
        } else {
          throw new Error(
            `Change note commitment ${inp.commitmentHex} not yet on-chain. Wait for blockchain indexing.`
          );
        }
      } else {
        throw new Error(
          `No on-chain NoteRecord found for commitment ${inp.commitmentHex}`
        );
      }
    } else {
      inp.treeIndex = idx;
    }
  }

  const maxLeaves = 1 << TREE_DEPTH;

  if (nextIndexOnChain > maxLeaves) {
    throw new Error("Tree depth too small for current next_index");
  }

  const leaves = new Array(maxLeaves).fill(null);

  for (const nr of noteRecords) {
    if (nr.index >= maxLeaves) continue;
    leaves[nr.index] = nr.commitment;
  }

  for (let i = 0; i < maxLeaves; i++) {
    if (!leaves[i]) leaves[i] = zeroLeaf;
  }

  for (let i = 0; i < nextIndexOnChain; i++) {
    if (leaves[i].equals(zeroLeaf)) {
      throw new Error(
        `Missing non-zero commitment for leaf index ${i} (< next_index)`
      );
    }
  }

  const { levels, root: poseidonRoot } =
    buildFullMerkleTreeFromLeaves(
      leaves,
      poseidonFr,
      zeroLeaf,
      nextIndexOnChain
    );

  console.log(
    "[tree] Simulated Poseidon root:",
    poseidonRoot.toString("hex")
  );
  console.log(
    "[tree] On-chain (Keccak) root: ",
    onChainRootBytes.toString("hex")
  );
  console.log(
    "[tree] NOTE: using Poseidon root for the zk circuit (debug mode)."
  );

  const rootFe = frFrom32be(poseidonRoot);
  const rootFr = toFr(rootFe);
  const rootStr = rootFr.toString();

  console.log(
    "[client] merkleRoot (field):",
    "0x" + rootFr.toString(16)
  );

  const inBalance = new Array(N_INS).fill("0");
  const inSpendNonce = new Array(N_INS).fill("0");
  const inputNullifier = new Array(N_INS).fill(0n);
  const inNoteNonce = new Array(N_INS).fill("0");
  const noteCommit = new Array(N_INS).fill(0n);

  for (let i = 0; i < N_INS; i++) {
    let spendNonceU64 = 0n;
    let noteNonceBi = 0n;
    let balBi = 0n;

    if (i < inputs.length) {
      const inp = inputs[i];

      balBi = BigInt(inp.balance);
      noteNonceBi = BigInt(inp.noteNonce);

      spendNonceU64 = noteNonceBi & (TWO64 - 1n);
    } else if (inputs.length > 0) {
      const firstInp = inputs[0];
      noteNonceBi = BigInt(firstInp.noteNonce);
      spendNonceU64 = noteNonceBi & (TWO64 - 1n);
    }
    
    inBalance[i] = balBi.toString();
    inNoteNonce[i] = noteNonceBi.toString();
    inSpendNonce[i] = spendNonceU64.toString();

    const nc = poseidonFr([balBi, noteNonceBi]);
    noteCommit[i] = nc;

    const nul = poseidonFr([VIEW_PRIV, spendNonceU64]);
    inputNullifier[i] = nul;
  }

  const outAmount = new Array(N_OUTS).fill("0");
  const outNoteNonce = new Array(N_OUTS).fill("0");
  const outputCommitment = new Array(N_OUTS).fill(0n);

  const zeroZeroCommit = poseidonFr([0n, 0n]);

  const viewPubPoint = BJ.mulPointEscalar(BJ.Base8, VIEW_PRIV);
  const VIEW_PUB = [
    BigInt(BJ.F.toObject(viewPubPoint[0])),
    BigInt(BJ.F.toObject(viewPubPoint[1]))
  ];

  let changeNoteData = null;

  if (!isFullWithdraw && REMAIN > 0n) {
    const changeNoteNonce = BigInt("0x" + crypto.randomBytes(32).toString("hex"));
    
    outAmount[0] = REMAIN.toString();
    outNoteNonce[0] = changeNoteNonce.toString();
    
    const changeCommitment = poseidonFr([REMAIN, changeNoteNonce]);
    outputCommitment[0] = changeCommitment;
    
    const ownerPk = inputs[0].ownerPk;
    
    const encryptedMemo = buildChangeNoteMemo(VIEW_PUB, REMAIN, changeNoteNonce, ownerPk);
    
    changeNoteData = {
      balance: REMAIN,
      noteNonce: changeNoteNonce,
      commitmentHex: "0x" + frTo32(changeCommitment, true).toString("hex"),
      encryptedMemo,
    };
    
    console.log(`[client] 💰 Partial withdrawal - creating change note`);
    console.log(`[client] Change amount: ${REMAIN} lamports`);
    console.log(`[client] Commitment: ${changeNoteData.commitmentHex}`);
    console.log(`[client] Commitment: ${changeNoteData.commitmentHex}`);
    
    for (let j = 1; j < N_OUTS; j++) {
      outputCommitment[j] = zeroZeroCommit;
    }
  } else {
    for (let j = 0; j < N_OUTS; j++) {
      outputCommitment[j] = zeroZeroCommit;
    }
  }

  const extAmountIn = 0n;
  const publicAmount = WITHDRAW;

  const destLimbs = limbsFromPubkey(recipientPk.toBase58());

  const inPathIndex = Array.from({ length: N_INS }, () =>
    new Array(TREE_DEPTH).fill("0")
  );
  const inPathElements = Array.from({ length: N_INS }, () =>
    new Array(TREE_DEPTH).fill("0x" + "0".repeat(64))
  );

  for (let i = 0; i < inputs.length; i++) {
    const inp = inputs[i];
    const treeIdx = inp.treeIndex;

    const { pathElements, pathIndexBits } =
      computeMerklePath(levels, treeIdx);

    inPathElements[i] = pathElements;
    inPathIndex[i] = pathIndexBits;
  }

  for (let i = inputs.length; i < N_INS; i++) {
    inPathElements[i] = [...inPathElements[0]];
    inPathIndex[i] = [...inPathIndex[0]];
  }

  const proverInput = {
    inBalance,
    inSpendNonce,
    inNoteNonce,
    receiverViewPriv: frStr(VIEW_PRIV),
    inPathElements,
    inPathIndex,
    merkleRoot: rootStr,
    outAmount,
    outNoteNonce,
    destLimbs: destLimbs.map((x) => x.toString()),
    extAmountIn: extAmountIn.toString(),
    publicAmount: publicAmount.toString(),
    inputNullifier: inputNullifier.map((x) => frStr(x)),
    outputCommitment: outputCommitment.map((x) => frStr(x)),
  };

  fs.writeFileSync(
    "debug_prover_input.json",
    JSON.stringify(proverInput, null, 2)
  );
  console.log("[debug] wrote prover input to debug_prover_input.json");

  console.log("[client] Proving join-split...");

  const proveOut = await groth16.fullProve(proverInput, WASM, ZKEY);

  const { proof, publicSignals } = proveOut;

  console.log(
    "[client] Proof done. publicSignals.length =",
    publicSignals.length
  );

  const publicStrings = publicSignals.map(String);
  const [
    merkleRootPub,
    inputNull0,
    inputNull1,
    inputNull2,
    inputNull3,
    inputNull4,
    inputNull5,
    dest0,
    dest1,
    dest2,
    dest3,
    outC0,
    outC1,
    outC2,
    outC3,
    outC4,
    outC5,
    publicAmountPub,
    extAmountInPub,
  ] = publicStrings;

  console.log("─────────────────────────────────────────────");
  console.log("[debug] CIRCUIT PUBLIC SIGNALS (Fr)");
  console.log("merkleRootPub =", merkleRootPub);
  console.log("inputNullifier[0..5] =", inputNull0, inputNull1, inputNull2, inputNull3, inputNull4, inputNull5);
  console.log("dest limbs pub =", dest0, dest1, dest2, dest3);
  console.log("out commitments =", outC0, outC1, outC2, outC3, outC4, outC5);
  console.log("publicAmountPub =", publicAmountPub);
  console.log("extAmountInPub =", extAmountInPub);
  console.log("─────────────────────────────────────────────");

  const fail = (label, circ, js) => {
    if (circ !== js) {
      throw new Error(
        `${label} mismatch:\n  circuit=${circ}\n  js=${js}`
      );
    }
  };

  // Merkle + nullifier + amounts
  fail("merkleRoot", merkleRootPub, rootStr);
  fail("inputNullifier[0]", inputNull0, frStr(inputNullifier[0]));
  fail("publicAmount", publicAmountPub, publicAmount.toString());
  fail("extAmountIn", extAmountInPub, extAmountIn.toString());

  console.log("[client] ✓ All public signals validated");
  console.log("─────────────────────────────────────────────");

  const nonce = BigInt(
    "0x" + crypto.randomBytes(8).toString("hex")
  );

  const memoPacked = buildJoinSplitMemoPacked({
    proof,
    publicAmount,
    extAmountIn,
    nonce,
    nInputs,
    inputNullifier,
    outputCommitment,
    isFullWithdraw,
  });

  fs.writeFileSync(OUT_PATH, memoPacked);

  try {
    fs.writeFileSync(
      OUT_PATH.replace(/\.bin$/, ".pubs.json"),
      JSON.stringify(publicSignals ?? [], null, 2)
    );
  } catch (_) {}

  console.log(
    `[client] Wrote join-split FULL memo → ${OUT_PATH}`
  );

  let payerKp = null;

  if (process.env.PRIVATE_KEY) {
    const raw = String(process.env.PRIVATE_KEY).trim();
    const sk = raw.startsWith("[")
      ? Uint8Array.from(JSON.parse(raw))
      : bs58.decode(raw);

    payerKp = Keypair.fromSecretKey(sk);
  }

  await ensureEscrowHasForWithdraw(conn, payerKp, escrow, 0);

  const spentMemoFiles = inputs.map((i) => i.memoFile);

  if (/^true$/i.test(getEnv("OUT_ONLY", "false"))) {
    console.log("[client] OUT_ONLY=true → not sending to relayer.");
    console.log(
      "[client] After you confirm on-chain success, run a ledger-mark script to mark inputs as spent:"
    );
    spentMemoFiles.forEach((f) => console.log(" -", f));
    process.exit(0);
  }

  const wsUrl = RELAYER_WS;
  const ws = new WebSocket(wsUrl);

  await new Promise((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });

  const req = {
    id: crypto.randomUUID(),
    type: "withdraw_via_memo_join_split",
    programId: PROGRAM_ID_RAW,
    recipient: recipientPk.toBase58(),
    memoPackedBase64: Buffer.from(memoPacked).toString("base64"),
    publicSignals,
    statePda: statePk.toBase58(),
    poolPda: pdaPool().toBase58(),
    escrowPda: pdaEscrow().toBase58(),
    merkleRoot: poseidonRoot.toString("hex"),
  };

  ws.send(JSON.stringify(req));

  ws.on("message", async (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.id !== req.id) return;

      if (msg.ok) {
        const sig = msg.signature;
        console.log("[relayer] ✅ Withdrawal successful!");
        console.log("[relayer] Signature:", sig);
        console.log("");
        console.log("🔗 View on Solscan:");
        console.log(`   https://solscan.io/tx/${sig}?cluster=devnet`);
        console.log("");
        console.log("🔗 View on Solana Explorer:");
        console.log(`   https://explorer.solana.com/tx/${sig}?cluster=devnet`);
        console.log("");
        
        try {
          markNotesSpent(PROGRAM_ID_RAW, RPC_URL, spentMemoFiles);
          console.log("[ledger] ✅ Ledger updated - notes marked as spent");
          
          if (changeNoteData) {
            changeNoteData.withdrawalSig = sig;
            await saveChangeNote(PROGRAM_ID_RAW, RPC_URL, changeNoteData);
          }
        } catch (e) {
          console.warn("[ledger] ⚠️  Failed to update ledger:", e.message);
        }
        process.exit(0);
      } else {
        console.error("[relayer] error:", msg.error);
        if (msg.logs) {
          console.error("logs:", msg.logs);
        }
        process.exit(1);
      }
    } catch (e) {
      console.error("bad reply", e);
      process.exit(1);
    }
  });

  ws.on("error", (e) => {
    console.error("ws error", e);
    process.exit(1);
  });
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
