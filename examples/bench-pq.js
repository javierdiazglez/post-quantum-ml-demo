/**
 * Microbenchmark de una sola operación PQC (ms/op).
 * Útil para estimar presupuesto de CPU en serverless (Vercel/Cloudflare).
 * No sustituye los KATs ACVP: mide rendimiento, no conformidad.
 */
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const N = Number(process.env.BENCH_N || 50);
const msg = new TextEncoder().encode('bench-pq-token');

function meanMs(fn, n = N) {
  // Descartar cold start
  fn();
  const t0 = performance.now();
  for (let i = 0; i < n; i++) fn();
  return (performance.now() - t0) / n;
}

const kemKeys = ml_kem768.keygen();
const { cipherText } = ml_kem768.encapsulate(kemKeys.publicKey);
const dsaKeys = ml_dsa65.keygen();
const sig = ml_dsa65.sign(msg, dsaKeys.secretKey);

const rows = [
  ['ML-KEM-768 keygen', meanMs(() => ml_kem768.keygen())],
  ['ML-KEM-768 encapsulate', meanMs(() => ml_kem768.encapsulate(kemKeys.publicKey))],
  ['ML-KEM-768 decapsulate', meanMs(() => ml_kem768.decapsulate(cipherText, kemKeys.secretKey))],
  ['ML-DSA-65 keygen', meanMs(() => ml_dsa65.keygen())],
  ['ML-DSA-65 sign', meanMs(() => ml_dsa65.sign(msg, dsaKeys.secretKey))],
  ['ML-DSA-65 verify', meanMs(() => ml_dsa65.verify(sig, msg, dsaKeys.publicKey))]
];

console.log(`Microbenchmark PQC (media de ${N} ops, tras 1 warm-up)`);
console.log('Operación'.padEnd(28), 'ms/op');
console.log('-'.repeat(40));
for (const [name, ms] of rows) {
  console.log(name.padEnd(28), ms.toFixed(2));
}
