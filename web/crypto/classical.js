/** Criptografía clásica (RSA-OAEP / RSA-PSS 2048). */

import { secretsEqual } from './util.js';

async function exportSpki(key) {
  return new Uint8Array(await crypto.subtle.exportKey('spki', key));
}

async function exportPkcs8(key) {
  return new Uint8Array(await crypto.subtle.exportKey('pkcs8', key));
}

/**
 * Encapsulación de secreto clásica: RSA-OAEP 2048 (análogo pedagógico a un KEM).
 * Solo Alice tiene par; Bob cifra un secreto al azar con la PK de Alice.
 */
export async function classicalKeyExchange() {
  const aliceKeys = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );

  const bobSecret = crypto.getRandomValues(new Uint8Array(32));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, aliceKeys.publicKey, bobSecret)
  );
  const aliceSecret = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, aliceKeys.privateKey, ciphertext)
  );

  const publicKey = await exportSpki(aliceKeys.publicKey);
  const secretKey = await exportPkcs8(aliceKeys.privateKey);

  return {
    algorithm: 'RSA-OAEP 2048',
    nistLevel: '≈1 (clásico)',
    quantumSafe: false,
    alice: { publicKey, secretKey, sharedSecret: aliceSecret },
    bob: {
      publicKey: new Uint8Array(0),
      secretKey: new Uint8Array(0),
      sharedSecret: bobSecret
    },
    wire: { label: 'Ciphertext RSA-OAEP', value: ciphertext },
    match: secretsEqual(aliceSecret, bobSecret),
    sizes: {
      publicKey: publicKey.length,
      secretKey: secretKey.length,
      sharedSecret: aliceSecret.length,
      wire: ciphertext.length
    }
  };
}

/**
 * Firma clásica: RSA-PSS 2048 + SHA-256.
 */
export async function classicalSignVerify(messageBytes) {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  );

  const publicKey = await exportSpki(keyPair.publicKey);
  const secretKey = await exportPkcs8(keyPair.privateKey);
  const signAlgo = { name: 'RSA-PSS', saltLength: 32 };

  const signature = new Uint8Array(
    await crypto.subtle.sign(signAlgo, keyPair.privateKey, messageBytes)
  );

  const valid = await crypto.subtle.verify(
    signAlgo,
    keyPair.publicKey,
    signature,
    messageBytes
  );

  const tamperedMsg =
    messageBytes.length > 0
      ? (() => {
          const t = new Uint8Array(messageBytes);
          t[0] ^= 0xff;
          return t;
        })()
      : new TextEncoder().encode('x');

  const tamperedValid = await crypto.subtle.verify(
    signAlgo,
    keyPair.publicKey,
    signature,
    tamperedMsg
  );

  return {
    algorithm: 'RSA-PSS 2048',
    nistLevel: '≈1 (clásico)',
    quantumSafe: false,
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
