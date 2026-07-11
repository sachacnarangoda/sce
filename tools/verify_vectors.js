'use strict';
/*
 * Independent cross-language verifier for the SCE test vectors.
 *
 *   node tools/verify_vectors.js
 *
 * This is a SECOND, from-scratch implementation of SCE's deterministic parts
 * (canonical manifest encoding, MEMH, HKDF key derivation, and the key
 * commitment) written in JavaScript, with no shared code with the Python
 * package. If it reproduces every value in test_vectors.json, the specification
 * is genuinely reimplementable and interoperable -- not merely "a Python
 * library". This is the interoperability half of technical viability.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DOMAIN = Buffer.from('LDDP-SCE-v4');
const KDF_INFO_PREFIX = Buffer.from('LDDP-SCE|kdf-v4|');
const KDF_CANON_TAG = Buffer.from('LDDP-SCE|kdf-canon-v4');
const MANIFEST_TAG = Buffer.from('SCEMAN1');
const CORE_FIELDS = ['weights_hash', 'quantization', 'kernel_build_id',
                     'tensor_parallel', 'numerics_mode'];

function u32be(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0, 0); return b; }
function u64be(n) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; }

// NFC-normalise a string and length-prefix its UTF-8 bytes.
function encStr(s) {
  const b = Buffer.from(s.normalize('NFC'), 'utf8');
  return Buffer.concat([u32be(b.length), b]);
}

// Strict canonical manifest encoding -- must match ModelManifest.canonical_bytes.
function canonicalManifest(m) {
  const parts = [MANIFEST_TAG];
  for (const f of CORE_FIELDS) parts.push(encStr(m[f]));
  const extra = m.extra || {};
  const keys = Object.keys(extra).sort((a, b) =>
    Buffer.compare(Buffer.from(a.normalize('NFC'), 'utf8'),
                   Buffer.from(b.normalize('NFC'), 'utf8')));
  parts.push(u32be(keys.length));
  for (const k of keys) { parts.push(encStr(k)); parts.push(encStr(extra[k])); }
  return Buffer.concat(parts);
}

function sha3_256(buf) { return crypto.createHash('sha3-256').update(buf).digest(); }

function memh(m) { return sha3_256(canonicalManifest(m)); }

function lp(buf) {
  return Buffer.concat([u32be(buf.length), buf]);
}

// HKDF info string — must match _kdf_info in core.py (length-prefixed, hashed).
function kdfInfo(contextUtf8, epochId, memhBuf) {
  const canonical = Buffer.concat([
    KDF_CANON_TAG,
    lp(Buffer.from(contextUtf8, 'utf8')),
    lp(u64be(epochId)),
    lp(memhBuf),
  ]);
  return Buffer.concat([KDF_INFO_PREFIX, sha3_256(canonical)]);
}

// K_enc + commitment -- must match _derive_key_material.
// v4: the HKDF-extract salt is the per-seal salt carried in the header (read from
// the vector), NOT the epoch. The epoch still binds through the info string.
function deriveKeyMaterial(masterSecretHex, memhBuf, epochId, contextUtf8, saltHex) {
  const master = Buffer.from(masterSecretHex, 'hex');
  const salt = Buffer.from(saltHex, 'hex');
  const info = kdfInfo(contextUtf8, epochId, memhBuf);
  const material = Buffer.from(crypto.hkdfSync('sha3-256', master, salt, info, 64));
  const kEnc = material.subarray(0, 32);
  const kComHalf = material.subarray(32, 64);
  const commitment = sha3_256(Buffer.concat([DOMAIN, Buffer.from('|commit|'), kComHalf]));
  return { kEnc, commitment };
}

function main() {
  const vpath = path.join(__dirname, '..', 'test_vectors.json');
  const vectors = JSON.parse(fs.readFileSync(vpath, 'utf8'));
  let pass = 0, fail = 0;

  console.log(`\nVerifying ${vectors.cases.length} SCE vectors with an independent JS implementation\n` +
              '-'.repeat(66));
  vectors.cases.forEach((c, i) => {
    const checks = [];

    const canon = canonicalManifest(c.manifest).toString('hex');
    checks.push(['canonical', canon === c.canonical_manifest_hex]);

    const mh = memh(c.manifest);
    checks.push(['MEMH', mh.toString('hex') === c.memh_sha3_256_hex]);

    const { kEnc, commitment } = deriveKeyMaterial(
      c.master_secret_hex, mh, c.epoch_id, c.context_utf8, c.salt_hex);
    checks.push(['K_enc', kEnc.toString('hex') === c.k_enc_hex]);
    checks.push(['commitment', commitment.toString('hex') === c.key_commitment_hex]);

    const ok = checks.every(([, v]) => v);
    ok ? pass++ : fail++;
    const detail = checks.map(([n, v]) => `${n}:${v ? 'ok' : 'MISMATCH'}`).join('  ');
    console.log(`  case ${i} [ctx="${c.context_utf8}"]  ${ok ? 'PASS' : 'FAIL'}   ${detail}`);
  });
  console.log('-'.repeat(66));
  if (fail === 0) {
    console.log(`All ${pass} vectors reproduced exactly by the independent JS implementation.\n`);
    process.exit(0);
  } else {
    console.log(`${fail} vector(s) FAILED to reproduce.\n`);
    process.exit(1);
  }
}

main();
