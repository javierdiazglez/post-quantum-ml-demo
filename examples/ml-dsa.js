/**
 * Demo ML-DSA-65 (FIPS 204): generar claves, firmar y verificar.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const { publicKey, secretKey } = ml_dsa65.keygen();
const message = new TextEncoder().encode('Hola, mundo post-cuántico!');

const signature = ml_dsa65.sign(message, secretKey);
const isValid = ml_dsa65.verify(signature, message, publicKey);

const tampered = new TextEncoder().encode('Hola, mundo alterado!');
const isTamperedValid = ml_dsa65.verify(signature, tampered, publicKey);

console.log('Algoritmo: ML-DSA-65');
console.log('Nivel de seguridad NIST: 3');
console.log('Clave pública (bytes):', publicKey.length);
console.log('Clave secreta (bytes):', secretKey.length);
console.log('Firma (bytes):', signature.length);
console.log('Firma válida:', isValid);
console.log('Firma con mensaje alterado:', isTamperedValid);
