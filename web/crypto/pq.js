/**
 * Wrappers post-cuánticos con @noble/post-quantum (JS puro, FIPS 203/204).
 * Algoritmos NIST nivel 3: ML-KEM-768 y ML-DSA-65.
 */
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { secretsEqual } from './util.js';

const KEM = {
  name: 'ML-KEM-768',
  securityLevel: 3
};

const SIG = {
  name: 'ML-DSA-65',
  securityLevel: 3
};

/**
 * Intercambio / encapsulación de clave: ML-KEM-768 (FIPS 203).
 */
export async function pqKeyExchange() {
  const { publicKey, secretKey } = ml_kem768.keygen();
  const { cipherText, sharedSecret: bobSecret } = ml_kem768.encapsulate(publicKey);
  const aliceSecret = ml_kem768.decapsulate(cipherText, secretKey);

  return {
    algorithm: KEM.name,
    nistLevel: KEM.securityLevel,
    quantumSafe: true,
    alice: { publicKey, secretKey, sharedSecret: aliceSecret },
    bob: {
      publicKey: new Uint8Array(0),
      secretKey: new Uint8Array(0),
      sharedSecret: bobSecret
    },
    wire: { label: 'Ciphertext ML-KEM-768', value: cipherText },
    match: secretsEqual(aliceSecret, bobSecret),
    sizes: {
      publicKey: publicKey.length,
      secretKey: secretKey.length,
      sharedSecret: aliceSecret.length,
      wire: cipherText.length
    }
  };
}

/**
 * Firma post-cuántica: ML-DSA-65 (FIPS 204).
 */
export async function pqSignVerify(messageBytes) {
  const { publicKey, secretKey } = ml_dsa65.keygen();
  const signature = ml_dsa65.sign(messageBytes, secretKey);
  const valid = ml_dsa65.verify(signature, messageBytes, publicKey);

  const tampered =
    messageBytes.length > 0
      ? (() => {
          const t = new Uint8Array(messageBytes);
          t[0] ^= 0xff;
          return t;
        })()
      : new TextEncoder().encode('x');

  const tamperedValid = ml_dsa65.verify(signature, tampered, publicKey);

  return {
    algorithm: SIG.name,
    nistLevel: SIG.securityLevel,
    quantumSafe: true,
    publicKey,
    secretKey,
    signature,
    valid,
    tamperedValid,
    sizes: {
      publicKey: publicKey.length,
      secretKey: secretKey.length,
      signature: signature.length
    }
  };
}
