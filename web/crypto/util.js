export function secretsEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Extracto corto de bytes reales para mostrar en la UI. */
export function fingerprint(bytes, groups = 2) {
  if (!bytes || bytes.length === 0) return '-';
  const hex = bufToHex(bytes).slice(0, groups * 4).toUpperCase();
  return hex.match(/.{1,4}/g)?.join('-') ?? hex;
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
