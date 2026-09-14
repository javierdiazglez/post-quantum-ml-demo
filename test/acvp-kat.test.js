/**
 * Known Answer Tests (KAT) contra vectores oficiales NIST ACVP.
 *
 * Fuente: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
 * Fixtures filtrados: test/vectors/nist-acvp/ (solo ML-KEM-768 y ML-DSA-65).
 *
 * Cada caso toma entradas hex publicadas por NIST (prompt.json), ejecuta
 * @noble/post-quantum y exige igualdad byte-a-byte con expectedResults.json.
 * Eso es conformidad reproducible frente al estándar FIPS 203/204 — no un
 * certificado CAVP comercial.
 */
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), 'vectors', 'nist-acvp');

/** NIST publica todos los campos binarios en hex mayúsculas. */
function hexToBytes(hex) {
  if (!hex) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** FIPS 203 keygen usa el seed de 64 bytes `d || z`. */
function concatBytes(...arrs) {
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function equalBytes(a, b) {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/** Carga el par prompt (entradas) + expectedResults (respuestas NIST). */
function loadSuite(name) {
  const dir = join(ROOT, name);
  return {
    prompt: JSON.parse(readFileSync(join(dir, 'prompt.json'), 'utf8')),
    expected: JSON.parse(readFileSync(join(dir, 'expectedResults.json'), 'utf8'))
  };
}

/**
 * Empareja cada caso de prompt con su expected por tgId/tcId.
 * yield { group, prompt, expected } listo para assert.
 */
function* zipGroups(prompt, expected) {
  expect(prompt.testGroups.length).toBe(expected.testGroups.length);
  for (let i = 0; i < prompt.testGroups.length; i++) {
    const pg = prompt.testGroups[i];
    const eg = expected.testGroups[i];
    expect(eg.tgId).toBe(pg.tgId);
    const erByTc = new Map(eg.tests.map((t) => [t.tcId, t]));
    for (const t of pg.tests) {
      const er = erByTc.get(t.tcId);
      expect(er).toBeDefined();
      yield { group: pg, prompt: t, expected: er };
    }
  }
}

describe('NIST ACVP KAT — ML-KEM-768 (FIPS 203)', () => {
  // keyGen: seed (d||z) → encapsulation key (ek) + decapsulation key (dk)
  test('keyGen', () => {
    const { prompt, expected } = loadSuite('ML-KEM-keyGen-FIPS203');
    let n = 0;
    for (const t of zipGroups(prompt, expected)) {
      const seed = concatBytes(hexToBytes(t.prompt.d), hexToBytes(t.prompt.z));
      const { publicKey, secretKey } = ml_kem768.keygen(seed);
      expect(publicKey).toEqual(hexToBytes(t.expected.ek));
      expect(secretKey).toEqual(hexToBytes(t.expected.dk));
      n++;
    }
    expect(n).toBe(25);
  });

  // encapsulation: (ek, m) → ciphertext c + shared secret k
  // decapsulation: (dk, c) → shared secret k (debe coincidir con NIST)
  test('encapDecap', () => {
    const { prompt, expected } = loadSuite('ML-KEM-encapDecap-FIPS203');
    let nEncap = 0;
    let nDecap = 0;
    for (const t of zipGroups(prompt, expected)) {
      if (t.group.function === 'encapsulation') {
        const { cipherText, sharedSecret } = ml_kem768.encapsulate(
          hexToBytes(t.prompt.ek),
          hexToBytes(t.prompt.m)
        );
        expect(cipherText).toEqual(hexToBytes(t.expected.c));
        expect(sharedSecret).toEqual(hexToBytes(t.expected.k));
        nEncap++;
      } else if (t.group.function === 'decapsulation') {
        const sharedSecret = ml_kem768.decapsulate(
          hexToBytes(t.prompt.c),
          hexToBytes(t.prompt.dk)
        );
        expect(sharedSecret).toEqual(hexToBytes(t.expected.k));
        nDecap++;
      } else {
        throw new Error(`unexpected function ${t.group.function}`);
      }
    }
    expect(nEncap).toBe(25);
    expect(nDecap).toBe(10);
  });
});

describe('NIST ACVP KAT — ML-DSA-65 (FIPS 204)', () => {
  // keyGen: seed de 32 bytes → public key (pk) + secret key (sk)
  test('keyGen', () => {
    const { prompt, expected } = loadSuite('ML-DSA-keyGen-FIPS204');
    let n = 0;
    for (const t of zipGroups(prompt, expected)) {
      const { publicKey, secretKey } = ml_dsa65.keygen(hexToBytes(t.prompt.seed));
      expect(publicKey).toEqual(hexToBytes(t.expected.pk));
      expect(secretKey).toEqual(hexToBytes(t.expected.sk));
      n++;
    }
    expect(n).toBe(25);
  });

  // sigGen (external, pure): sin rnd → firmas deterministas (extraEntropy: false);
  // con rnd → firmas hedged (extraEntropy = esos 32 bytes). context = domain separation.
  test('sigGen', () => {
    const { prompt, expected } = loadSuite('ML-DSA-sigGen-FIPS204');
    let n = 0;
    for (const t of zipGroups(prompt, expected)) {
      const extraEntropy = t.prompt.rnd ? hexToBytes(t.prompt.rnd) : false;
      const context = t.prompt.context ? hexToBytes(t.prompt.context) : undefined;
      const sig = ml_dsa65.sign(hexToBytes(t.prompt.message), hexToBytes(t.prompt.sk), {
        extraEntropy,
        context
      });
      expect(sig).toEqual(hexToBytes(t.expected.signature));
      n++;
    }
    expect(n).toBe(30);
  });

  // sigVer: verify(sig, msg, pk) debe devolver exactamente testPassed de NIST
  // (incluye casos negativos donde la firma/mensaje son inválidos).
  test('sigVer', () => {
    const { prompt, expected } = loadSuite('ML-DSA-sigVer-FIPS204');
    let nPass = 0;
    let nFail = 0;
    for (const t of zipGroups(prompt, expected)) {
      const context = t.prompt.context ? hexToBytes(t.prompt.context) : undefined;
      const valid = ml_dsa65.verify(
        hexToBytes(t.prompt.signature),
        hexToBytes(t.prompt.message),
        hexToBytes(t.prompt.pk),
        { context }
      );
      expect(valid).toBe(t.expected.testPassed);
      if (t.expected.testPassed) nPass++;
      else nFail++;
    }
    expect(nPass).toBe(3);
    expect(nFail).toBe(12);
  });
});

describe('Propiedades de rechazo (además de ACVP)', () => {
  // Rechazo de firmas inválidas: un solo bit alterado debe hacer fallar verify.
  test('ML-DSA-65: firma corrompida (1 bit) → verify false', () => {
    const { publicKey, secretKey } = ml_dsa65.keygen();
    const msg = new TextEncoder().encode('tranvia-validacion');
    const sig = ml_dsa65.sign(msg, secretKey);
    expect(ml_dsa65.verify(sig, msg, publicKey)).toBe(true);

    const corrupted = new Uint8Array(sig);
    corrupted[0] ^= 0x01;
    expect(ml_dsa65.verify(corrupted, msg, publicKey)).toBe(false);
  });

  // FIPS 203 rechazo implícito: ciphertext manipulado no lanza error;
  // decapsulate devuelve un secreto de 32 bytes distinto del original (anti-oráculo).
  test('ML-KEM-768: ciphertext corrompido → rechazo implícito', () => {
    const { publicKey, secretKey } = ml_kem768.keygen();
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);

    const corrupted = new Uint8Array(cipherText);
    corrupted[0] ^= 0x01;
    const rejected = ml_kem768.decapsulate(corrupted, secretKey);

    expect(rejected.length).toBe(32);
    expect(equalBytes(rejected, sharedSecret)).toBe(false);
  });
});
