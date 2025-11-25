#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require('fs');
const path = require('path');
const Keccak = require('keccak');

const PROGRAM_N_PUBLIC = 19;

const argv = process.argv.slice(2);
function getArg(flag, def) {
  const i = argv.indexOf(flag);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : def;
}

const manifestDir = process.cwd();
const srcDir = path.join(manifestDir, 'src');

const envVK = process.env.VK_JSON_PATH;
const cliVK = getArg('--vk', null);
const defaultVK = fs.existsSync(path.join(manifestDir, 'tests/circuits/privw_vk.json'))
  ? path.join(manifestDir, 'tests/circuits/privw_vk.json')
  : path.join(srcDir, 'vk.json');

const vkPath = path.resolve(cliVK ?? envVK ?? defaultVK);
const outPath = path.resolve(getArg('--out', path.join(srcDir, 'vk.rs')));

const order = 'swap';

console.log(`[vkgen] VK path : ${vkPath}`);
console.log(`[vkgen] G2 order: ${order} (snarkjs swap)`);
console.log(`[vkgen] Out file: ${outPath}`);

function feltToBE32(s) {
  const t = String(s).trim();
  const n = t.startsWith('0x') || t.startsWith('0X') ? BigInt(t) : BigInt(t);
  if (n < 0n) throw new Error('negative field element not supported');

  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const bytes = Buffer.from(hex, 'hex');
  if (bytes.length > 32) throw new Error('field element > 32 bytes');

  const out = Buffer.alloc(32, 0);
  bytes.copy(out, 32 - bytes.length);
  return out;
}

function fmtBytes(buf) {
  const parts = [];
  for (let i = 0; i < buf.length; i++) {
    parts.push('0x' + buf[i].toString(16).toUpperCase().padStart(2, '0'));
  }
  return '[' + parts.join(', ') + ']';
}

function g1Flat(x, y) {
  const xb = feltToBE32(x);
  const yb = feltToBE32(y);
  return Buffer.concat([xb, yb]);
}

function g2FlatSwap(fp2) {
  const x1 = feltToBE32(fp2[0][1]);
  const x0 = feltToBE32(fp2[0][0]);
  const y1 = feltToBE32(fp2[1][1]);
  const y0 = feltToBE32(fp2[1][0]);
  return Buffer.concat([x1, x0, y1, y0]);
}

const k256 = (buf) => '0x' + Keccak('keccak256').update(buf).digest('hex');

if (!fs.existsSync(vkPath)) {
  throw new Error(`VK file not found at ${vkPath}`);
}
const vk = JSON.parse(fs.readFileSync(vkPath, 'utf8'));

if (vk.curve !== 'bn128') {
  throw new Error(`VK curve must be bn128 (BN254), got ${vk.curve}`);
}

if (vk.nPublic !== PROGRAM_N_PUBLIC) {
  throw new Error(`VK expects ${vk.nPublic} public inputs, but program uses ${PROGRAM_N_PUBLIC}`);
}

if (!vk.IC || vk.IC.length !== vk.nPublic + 1) {
  throw new Error(
    `IC length must be nPublic + 1 (got ${vk.IC ? vk.IC.length : 0}, expected ${vk.nPublic + 1})`
  );
}

const alpha_g1 = g1Flat(vk.vk_alpha_1[0], vk.vk_alpha_1[1]);
const beta_g2  = g2FlatSwap(vk.vk_beta_2);
const gamma_g2 = g2FlatSwap(vk.vk_gamma_2);
const delta_g2 = g2FlatSwap(vk.vk_delta_2);

const h = Keccak('keccak256');
h.update(alpha_g1);
h.update(beta_g2);
h.update(gamma_g2);
h.update(delta_g2);
for (const p of vk.IC) {
  h.update(g1Flat(p[0], p[1]));
}
const vkHashHex = '0x' + h.digest('hex');

console.log('[vkgen] KECCAK alpha_g1 =', k256(alpha_g1));
console.log('[vkgen] KECCAK beta_g2  =', k256(beta_g2));
console.log('[vkgen] KECCAK gamma_g2 =', k256(gamma_g2));
console.log('[vkgen] KECCAK delta_g2 =', k256(delta_g2));
console.log(`[vkgen] VK_HASH_HEX (${order}) =`, vkHashHex);

let out = '';
out += '//! AUTO-GENERATED from VK JSON. DO NOT EDIT.\n';
out += '#![allow(clippy::all, non_upper_case_globals)]\n\n';
out += `pub const VK_NR_PUBINPUTS: usize = ${vk.nPublic};\n`;
out += `pub const VK_HASH_HEX: &str = "${vkHashHex}";\n\n`;

out += `pub const VK_ALPHA_G1: [u8; 64] = ${fmtBytes(alpha_g1)};\n`;
out += `pub const VK_BETA_G2:  [u8; 128] = ${fmtBytes(beta_g2)};\n`;
out += `pub const VK_GAMME_G2: [u8; 128] = ${fmtBytes(gamma_g2)};\n`;
out += `pub const VK_DELTA_G2: [u8; 128] = ${fmtBytes(delta_g2)};\n\n`;

out += `pub static VK_IC: [[u8; 64]; ${vk.IC.length}] = [\n`;
for (const p of vk.IC) {
  out += '    ' + fmtBytes(g1Flat(p[0], p[1])) + ',\n';
}
out += '];\n';

fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, out);
console.log(`[vkgen] Wrote ${outPath}`);
