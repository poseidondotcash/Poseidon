#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bs58 = require("bs58");
const nacl = require("tweetnacl");
require("dotenv").config();

const {
  Connection, Keypair, PublicKey, SystemProgram,
  Transaction, TransactionInstruction, sendAndConfirmTransaction,
  ComputeBudgetProgram
} = require("@solana/web3.js");

const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const must = (v, msg) => { if (!v) throw new Error(msg); return v; };
const getEnv = (k, def) => process.env[k] ?? def;
const arg = (k, def) => {
  const i = process.argv.indexOf("--" + k);
  return (i > -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--"))
    ? process.argv[i + 1]
    : getEnv(k.toUpperCase(), def);
};
const anchorIxDisc = (name) => sha256(Buffer.from(`global:${name}`)).subarray(0, 8);
const frTo32 = (dec, be) => {
  let x = BigInt(dec);
  const out = Buffer.alloc(32, 0);
  if (be) {
    for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  } else {
    let i = 0;
    while (x > 0n && i < 32) { out[i++] = Number(x & 0xffn); x >>= 8n; }
  }
  return out;
};
const beOrLe32FromBig = (xIn, little = true) => {
  let x = BigInt(xIn);
  const out = Buffer.alloc(32);
  if (little) {
    for (let i = 0; i < 32; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
  } else {
    for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  }
  return out;
};
const u32leToBig = (buf) => {
  let x = 0n;
  for (let i = 0; i < 32; i++) x |= BigInt(buf[i] || 0) << (8n * BigInt(i));
  return x;
};

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

const PRIVATE_KEY_RAW = must(getEnv("PRIVATE_KEY"), "Set PRIVATE_KEY in .env");
const PROGRAM_ID_RAW  = must(getEnv("PROGRAM_ID"),  "Set PROGRAM_ID in .env");

const RPC_URL          = arg("rpc", "https://api.devnet.solana.com");
const DEPOSIT_LAMPORTS = BigInt(arg("amount", getEnv("DEPOSIT_LAMPORTS", "2000000")));
const RAW_MEMO_OUT     = arg("memo-out", getEnv("MEMO_OUT", ""));
const MEMO_OUT         = RAW_MEMO_OUT || `deposit_memo_${Date.now()}.bin`;
const ESCROW_SAFETY    = Number(getEnv("ESCROW_SAFETY", "3000000"));
const WALLET_STATE     = getEnv("WALLET_STATE", "wallet_state.json");

const PROGRAM   = new PublicKey(PROGRAM_ID_RAW);
const pdaState  = () => PublicKey.findProgramAddressSync([Buffer.from("state")],  PROGRAM)[0];
const pdaEscrow = () => PublicKey.findProgramAddressSync([Buffer.from("escrow")], PROGRAM)[0];
const pdaPool   = () => PublicKey.findProgramAddressSync([Buffer.from("pool")],  PROGRAM)[0];

async function loadCircom() {
  let lib = null;
  try { lib = require("circomlibjs-pure"); } catch(_) {}
  if (!lib) { try { lib = require("circomlibjs"); } catch(_) {} }
  if (!lib) throw new Error("Install circomlibjs or circomlibjs-pure");
  const BJ =
    lib.babyJub ||
    lib.babyjub ||
    (typeof lib.buildBabyjub === "function" ? await lib.buildBabyjub() : null) ||
    (typeof lib.buildBabyJub === "function" ? await lib.buildBabyJub() : null);
  const Poseidon =
    lib.poseidon ||
    (typeof lib.buildPoseidon === "function" ? await lib.buildPoseidon() : null);
  if (!BJ || !Poseidon) throw new Error("Failed to load babyJub/poseidon");
  return { BJ, Poseidon };
}

async function deriveViewPrivFromSolanaSk(secretKey) {
  const { BJ } = await loadCircom();
  const subOrder = BigInt(BJ.subOrder);
  let skHash = BigInt("0x" + sha256(secretKey).toString("hex")) % subOrder;
  if (skHash === 0n) skHash = 1n;
  const pub = BJ.mulPointEscalar(BJ.Base8, skHash);
  return {
    viewPriv: skHash,
    viewPub: [BigInt(BJ.F.toObject(pub[0])), BigInt(BJ.F.toObject(pub[1]))],
  };
}

async function buildNoteCiphertext(viewPub, balance, noteNonce, ownerPubkey) {
  const { BJ } = await loadCircom();
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

  if (!(ownerPubkey instanceof PublicKey)) throw new Error("ownerPubkey must be a PublicKey");
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

async function openNoteCiphertext(memo, viewPriv) {
  const { BJ } = await loadCircom();
  if (memo.length < 4 + 32 + 32 + 24 + 16) throw new Error("memo too short");
  if (memo.subarray(0,4).toString("utf8") !== "PWV1") throw new Error("bad memo tag");
  const eX = u32leToBig(memo.subarray(4, 36));
  const eY = u32leToBig(memo.subarray(36, 68));
  const nonce = memo.subarray(68, 92);
  const box = memo.subarray(92);
  const shared = BJ.mulPointEscalar([BJ.F.e(eX), BJ.F.e(eY)], viewPriv);
  const sX = BigInt(BJ.F.toObject(shared[0]));
  const sY = BigInt(BJ.F.toObject(shared[1]));
  const key = sha256(Buffer.concat([
    Buffer.from("privw:v1"),
    beOrLe32FromBig(sX, true),
    beOrLe32FromBig(sY, true)
  ]));
  const opened = nacl.secretbox.open(
    new Uint8Array(box),
    new Uint8Array(nonce),
    new Uint8Array(key)
  );
  if (!opened) throw new Error("ciphertext auth failed");

  const buf = Buffer.from(opened);
  if (buf.length < 32 + 32 + 32) throw new Error("decrypted memo payload too short");
  const balance = u32leToBig(buf.subarray(0,32));
  const noteNonce = u32leToBig(buf.subarray(32,64));
  const ownerBytes = buf.subarray(64, 96);
  const ownerPubkey = new PublicKey(ownerBytes);

  return { balance, noteNonce, ownerPubkey };
}

function readKeypair(raw) {
  const t = String(raw).trim();
  const bytes = t.startsWith("[") ? Uint8Array.from(JSON.parse(t)) : bs58.decode(t);
  return Keypair.fromSecretKey(bytes);
}

function ixInitState(payer) {
  const disc = anchorIxDisc("init_state");
  return new TransactionInstruction({
    programId: PROGRAM,
    keys: [
      { pubkey: pdaState(),  isSigner: false, isWritable: true },
      { pubkey: pdaEscrow(), isSigner: false, isWritable: true },
      { pubkey: pdaPool(),   isSigner: false, isWritable: true },
      { pubkey: payer,       isSigner: true,  isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: disc,
  });
}

function ixDepositWithNote(state, pool, escrow, depositor, amountU64, commitmentBe32, ciphertext) {
  const notePda = PublicKey.findProgramAddressSync(
    [Buffer.from("note"), commitmentBe32],
    PROGRAM
  )[0];
  const disc = anchorIxDisc("deposit_with_note");
  const amountLE = Buffer.alloc(8); amountLE.writeBigUInt64LE(BigInt(amountU64), 0);
  const ctLenLE  = Buffer.alloc(4); ctLenLE.writeUInt32LE(ciphertext.length, 0);
  const data = Buffer.concat([disc, amountLE, commitmentBe32, ctLenLE, ciphertext]);
  return new TransactionInstruction({
    programId: PROGRAM,
    keys: [
      { pubkey: state,     isSigner: false, isWritable: true },
      { pubkey: pool,      isSigner: false, isWritable: true },
      { pubkey: escrow,    isSigner: false, isWritable: true },
      { pubkey: depositor, isSigner: true,  isWritable: true },
      { pubkey: notePda,   isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

async function ensureEscrowHasForNote(connection, payerKp, escrowPk, memoLength) {
  const noteSpace = 8 + 1 + 4 + 32 + 4 + memoLength;
  const rentForNote = await connection.getMinimumBalanceForRentExemption(noteSpace);
  const mustHave = rentForNote + ESCROW_SAFETY;
  const escrowInfo = await connection.getAccountInfo(escrowPk);
  const current = escrowInfo?.lamports ?? 0;

  if (current < mustHave) {
    const need = mustHave - current;
    const tx = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: payerKp.publicKey,
        toPubkey: escrowPk,
        lamports: need
      })
    );
    await sendAndConfirmTransaction(connection, tx, [payerKp]);
    console.log(`Topped up ESCROW by ${need} lamports (target >= ${mustHave}).`);
  }
}

function explorerTxUrl(sig, rpcUrl) {
  const cluster =
    /devnet/i.test(rpcUrl) ? "devnet" :
    /testnet/i.test(rpcUrl) ? "testnet" :
    "mainnet";
  return `https://explorer.solana.com/tx/${sig}?cluster=${cluster}`;
}

(async () => {
  const payer = readKeypair(PRIVATE_KEY_RAW);
  const conn = new Connection(RPC_URL, "confirmed");

  const state  = pdaState();
  const escrow = pdaEscrow();
  const pool   = pdaPool();

  console.log("RPC_URL     :", RPC_URL);
  console.log("PROGRAM_ID  :", PROGRAM.toBase58());
  console.log("PAYER       :", payer.publicKey.toBase58());
  console.log("STATE PDA   :", state.toBase58());
  console.log("ESCROW PDA  :", escrow.toBase58());
  console.log("POOL PDA    :", pool.toBase58());
  console.log("AMOUNT      :", DEPOSIT_LAMPORTS.toString(), "lamports");
  console.log("MEMO_OUT    :", MEMO_OUT);
  console.log("WALLET_STATE:", WALLET_STATE);
  console.log("LEDGER_FILE :", scopedLedgerPath(PROGRAM_ID_RAW, RPC_URL));

  const stateInfo = await conn.getAccountInfo(state);
  if (!stateInfo) {
    console.log("Initializing PDAs (state, escrow, pool)...");
    const tx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }),
      ixInitState(payer.publicKey),
    );
    const sig = await sendAndConfirmTransaction(conn, tx, [payer]);
    console.log("PDAs initialized. Sig:", sig, "\n", explorerTxUrl(sig, RPC_URL));
  } else {
    console.log("State already initialized.");
  }

  const { BJ, Poseidon } = await loadCircom();
  const { viewPriv, viewPub } = await deriveViewPrivFromSolanaSk(payer.secretKey);

  let NOTE_NONCE_256 =
    BigInt("0x" + crypto.randomBytes(32).toString("hex")) % BigInt(BJ.subOrder);
  if (NOTE_NONCE_256 === 0n) NOTE_NONCE_256 = 1n;

  const noteCommitFe = Poseidon([
  DEPOSIT_LAMPORTS,   // inBalance
  NOTE_NONCE_256,     // inNoteNonce
]);

  const depositCommitment = BigInt(BJ.F.toObject(noteCommitFe));
  const commitmentBE = frTo32(depositCommitment, true);


  const memoBuf = await buildNoteCiphertext(
    viewPub,
    DEPOSIT_LAMPORTS,
    NOTE_NONCE_256,
    payer.publicKey
  );

  fs.writeFileSync(MEMO_OUT, memoBuf);
  fs.writeFileSync("deposit_commitment.hex", "0x" + commitmentBE.toString("hex"));
  console.log("Saved memo ->", MEMO_OUT);

  await ensureEscrowHasForNote(conn, payer, escrow, memoBuf.length);

  const tx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_200_000 }),
    ixDepositWithNote(state, pool, escrow, payer.publicKey, DEPOSIT_LAMPORTS, commitmentBE, memoBuf)
  );
  const sig = await sendAndConfirmTransaction(conn, tx, [payer]);
  const url = explorerTxUrl(sig, RPC_URL);
  console.log("Deposit sent, leaf inserted, ciphertext stored on-chain.");
  console.log("Tx Signature:", sig);
  console.log("Explorer   :", url);

  const slot = await conn.getSlot("confirmed");
  const { balance, noteNonce, ownerPubkey } = await openNoteCiphertext(memoBuf, viewPriv);
  console.log("Decrypted memo:");
  console.log("  balance (lamports):", balance.toString());
  console.log("  note nonce (u256) :", noteNonce.toString());
  console.log("  owner (base58)    :", ownerPubkey.toBase58());

  const receipt = {
    signature: sig,
    explorer_url: url,
    slot,
    amount_lamports: balance.toString(),
    owner: ownerPubkey.toBase58(),
    commitment_hex_be: "0x" + Buffer.from(commitmentBE).toString("hex"),
    memo_path: MEMO_OUT,
    note_nonce: noteNonce.toString(),
    created_at: new Date().toISOString(),
  };
  const receiptPath = `deposit_receipt_${sig}.json`;
  fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));
  console.log("Saved", receiptPath);

  let wallet = { version: 1, total_balance: "0", notes: [] };
  if (fs.existsSync(WALLET_STATE)) {
    try {
      wallet = JSON.parse(fs.readFileSync(WALLET_STATE, "utf8"));
    } catch (e) {
      console.warn("Failed to parse existing wallet_state.json, starting fresh:", e.message);
    }
  }

  const prevTotal = BigInt(wallet.total_balance || "0");
  const newTotal  = prevTotal + balance;

  wallet.total_balance = newTotal.toString();
  wallet.notes.push({
    signature: sig,
    slot,
    amount_lamports: balance.toString(),
    commitment_hex_be: "0x" + Buffer.from(commitmentBE).toString("hex"),
    memo_path: MEMO_OUT,
    note_nonce: noteNonce.toString(),
    owner: ownerPubkey.toBase58(),
    created_at: receipt.created_at,
  });

  fs.writeFileSync(WALLET_STATE, JSON.stringify(wallet, null, 2));
  console.log("Updated", WALLET_STATE, "-> total_balance:", wallet.total_balance, "lamports");

  const cluster = clusterTagFromRpc(RPC_URL);
  let ledger = readLedgerSafeScoped(PROGRAM_ID_RAW, RPC_URL);
  if (!Array.isArray(ledger.notes)) ledger.notes = [];

  const stateAi = await conn.getAccountInfo(pdaState());
  if (!stateAi) throw new Error("Failed to read state after deposit");
  const nextIndex = stateAi.data.readUInt32LE(8 + 32 + 1 + 1 + 1);
  const treeIndex = nextIndex - 1;
  console.log("[ledger] Assigned treeIndex:", treeIndex);

  ledger.notes.push({
    memoFile: MEMO_OUT,
    balance: Number(balance),
    spent: false,
    nullifier: null,
    owner: ownerPubkey.toBase58(),
    commitment: "0x" + Buffer.from(commitmentBE).toString("hex"),
    noteNonce: noteNonce.toString(),
    signature: sig,
    slot,
    createdAt: receipt.created_at,
    treeIndex,
  });

  const totalUnspent = (ledger.notes || [])
    .filter(n => !n.spent && n.balance > 0)
    .reduce((acc, n) => acc + BigInt(n.balance), 0n);
  const ledgerPath = writeLedger(PROGRAM_ID_RAW, RPC_URL, ledger);
  console.log(`[ledger] Updated -> ${ledgerPath} (total unspent: ${totalUnspent})`);

  console.log("Done.");
})().catch((e) => { console.error(e); process.exit(1); });