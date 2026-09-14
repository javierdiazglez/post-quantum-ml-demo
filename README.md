# Post-Quantum ML Demo

## Algoritmos post-cuánticos implementados

Demostración interactiva (Alice y Bob) de criptografía clásica frente a post-cuántica NIST nivel 3. Se emplean ML-KEM y ML-DSA mediante [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) (JavaScript puro, sin WASM).

| Necesidad | Clásico (vulnerable a QC) | Post-cuántico |
|-----------|---------------------------|---------------|
| Intercambio / encapsulación de secreto | RSA-OAEP 2048 | **ML-KEM-768** (FIPS 203, NIST nivel 3) |
| Firmas digitales | RSA-PSS 2048 | **ML-DSA-65** (FIPS 204, NIST nivel 3) |

- **ML-KEM** (*Module-Lattice Key-Encapsulation Mechanism*; anteriormente CRYSTALS-Kyber, FIPS 203): mecanismo de encapsulación de clave. Variante utilizada: **ML-KEM-768** (NIST nivel 3).
- **ML-DSA** (*Module-Lattice Digital Signature Algorithm*; anteriormente CRYSTALS-Dilithium, FIPS 204): firmas digitales. Variante utilizada: **ML-DSA-65** (NIST nivel 3).

### Decisión de ingeniería

Se emplea [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum): implementación en JavaScript puro de ML-KEM (FIPS 203) y ML-DSA (FIPS 204), sin WASM ni prebuild nativo. Es compatible con navegador, Bun/Node y entornos React Native/Expo (con polyfill de `getRandomValues` cuando sea necesario).

Dependencia: `@noble/post-quantum` (MIT).

### Publicaciones de referencia NIST

NIST no distribuye un paquete npm oficial de ML-KEM / ML-DSA. Las publicaciones públicas de referencia son:

| Publicación NIST | Descripción |
|------------------|-------------|
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) / [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | Especificación normativa de los algoritmos |
| [ACVP-Server KATs](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files) | Vectores de prueba oficiales (Known Answer Tests); datos de referencia empleados por laboratorios CAVP |

El proyecto combina una implementación en JavaScript puro (`@noble/post-quantum`) con vectores ACVP versionados en [`test/vectors/nist-acvp/`](test/vectors/nist-acvp/), a fin de verificar la conformidad frente al estándar.

### Validación ACVP / KAT NIST

Se descargan los JSON oficiales, se filtran a **ML-KEM-768** y **ML-DSA-65**, y se comprueba byte a byte que `ml_kem768` y `ml_dsa65` reproducen las respuestas esperadas por NIST:

| Suite ACVP | Validación |
|------------|------------|
| `ML-KEM-keyGen-FIPS203` | `keygen(d\|\|z)` → `ek` / `dk` |
| `ML-KEM-encapDecap-FIPS203` | encapsulate / decapsulate → `c` / `k` |
| `ML-DSA-keyGen-FIPS204` | `keygen(seed)` → `pk` / `sk` |
| `ML-DSA-sigGen-FIPS204` | `sign` (external, pure) → `signature` |
| `ML-DSA-sigVer-FIPS204` | `verify` → `testPassed` |

Provenance y filtro: [`test/vectors/nist-acvp/SOURCE.md`](test/vectors/nist-acvp/SOURCE.md).

Ejecutar la validación:

```bash
bun test
# únicamente KATs ACVP:
bun run test:acvp
```

Regenerar los fixtures filtrados:

```bash
bun run vectors:fetch
```

#### Alcance de la validación

Si la suite termina correctamente, se demuestra que la implementación reproduce byte a byte las respuestas publicadas por NIST para ML-KEM-768 y ML-DSA-65 en los vectores ACVP incluidos. El resultado constituye una evidencia de conformidad reproducible frente a FIPS 203/204.

Dicha evidencia no constituye un certificado CAVP emitido por un laboratorio acreditado, ni sustituye una auditoría de seguridad, un análisis de canales laterales o una evaluación de idoneidad para entornos de producción.

Salida de referencia:

```
bun test v1.3.14

test\acvp-kat.test.js:
(pass) NIST ACVP KAT — ML-KEM-768 (FIPS 203) > keyGen
(pass) NIST ACVP KAT — ML-KEM-768 (FIPS 203) > encapDecap
(pass) NIST ACVP KAT — ML-DSA-65 (FIPS 204) > keyGen
(pass) NIST ACVP KAT — ML-DSA-65 (FIPS 204) > sigGen
(pass) NIST ACVP KAT — ML-DSA-65 (FIPS 204) > sigVer

 5 pass
 0 fail
 352 expect() calls
```

### Requisitos

* [Bun](https://bun.sh/) **1+**

### Arranque de la aplicación web

```bash
bun install
bun run dev
```

### Ejemplos de código (CLI)

Ejecutar las demos mínimas de cada algoritmo:

```bash
bun run demo:ml-kem
bun run demo:ml-dsa
```

Consultar también `examples/ml-kem.js` y `examples/ml-dsa.js`.

### Contexto

Un ordenador cuántico con el **algoritmo de Shor** podría romper RSA. **ML-KEM-768** y **ML-DSA-65** se diseñaron para resistir dicho escenario (NIST nivel 3 ≈ AES-192).