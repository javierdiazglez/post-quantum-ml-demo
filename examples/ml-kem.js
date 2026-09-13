/**
 * Demo ML-KEM-768 (FIPS 203): intercambio de clave compartida (KEM).
 *
 * Alice genera el par de claves.
 * Bob encapsula un secreto usando la clave pública de Alice.
 * Alice desencapsula y obtiene el mismo secreto compartido.
 */
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

const { publicKey, secretKey } = ml_kem768.keygen();
const { cipherText, sharedSecret: bobSecret } = ml_kem768.encapsulate(publicKey);
const aliceSecret = ml_kem768.decapsulate(cipherText, secretKey);

const secretsMatch =
  aliceSecret.length === bobSecret.length &&
  aliceSecret.every((byte, i) => byte === bobSecret[i]);

console.log('Algoritmo: ML-KEM-768');
console.log('Nivel de seguridad NIST: 3');
console.log('Clave pública (bytes):', publicKey.length);
console.log('Clave secreta (bytes):', secretKey.length);
console.log('Ciphertext (bytes):', cipherText.length);
console.log('Secreto compartido (bytes):', bobSecret.length);
console.log('Secretos coinciden:', secretsMatch);
console.log('Secreto (hex):', Buffer.from(bobSecret).toString('hex'));
