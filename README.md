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

Se descargan los JSON oficiales, se filtran a **ML-KEM-768** y **ML-DSA-65**, y se comprueba byte a byte que `ml_kem768` y `ml_dsa65` reproducen las respuestas esperadas por NIST.

| Suite ACVP | Casos | Validación / notas |
|------------|------:|--------------------|
| `ML-KEM-keyGen-FIPS203` | 25 | `keygen(d\|\|z)` → `ek` / `dk` |
| `ML-KEM-encapDecap-FIPS203` | 35 | 25 encapsulation + 10 decapsulation → `c` / `k` |
| `ML-DSA-keyGen-FIPS204` | 25 | `keygen(seed)` → `pk` / `sk` |
| `ML-DSA-sigGen-FIPS204` | 30 | 15 deterministas + 15 hedged; mensajes de 1–8192 bytes |
| `ML-DSA-sigVer-FIPS204` | 15 | 3 válidos + **12 inválidos** (`testPassed: false`) |

Además de los KATs, se comprueban propiedades de rechazo propias:

- **ML-DSA-65:** una firma alterada en un solo bit debe hacer que `verify` devuelva `false`.
- **ML-KEM-768:** un ciphertext alterado en un solo bit activa el **rechazo implícito** de FIPS 203: `decapsulate` no lanza error y devuelve un secreto de 32 bytes distinto del original (mitigación de oráculos de decapsulación).

Ejecutar la validación:

```bash
bun test
# únicamente KATs ACVP y rechazo:
bun run test:acvp
```

Regenerar los fixtures filtrados:

```bash
bun run vectors:fetch
```

#### Alcance de la validación

Si la suite termina correctamente, se demuestra que la implementación reproduce byte a byte las respuestas publicadas por NIST para ML-KEM-768 y ML-DSA-65 en los vectores ACVP incluidos, y que rechaza correctamente firmas y ciphertexts manipulados. El resultado constituye una evidencia de conformidad reproducible frente a FIPS 203/204.

Dicha evidencia no constituye un certificado CAVP emitido por un laboratorio acreditado, ni sustituye una auditoría de seguridad, un análisis de canales laterales o una evaluación de idoneidad para entornos de producción.

#### Tiempos observados y Fiat-Shamir with Aborts

En la ejecución de referencia, `sigGen` (~523 ms para 30 vectores) es sistemáticamente más lento que `keyGen` / `sigVer`. Ese comportamiento es coherente con el esquema **Fiat-Shamir with Aborts** de ML-DSA: la firma genera candidatos y los descarta si no cumplen el chequeo de norma, con un número medio de iteraciones del orden de ~5 para ML-DSA-65 ([arxiv.org/pdf/2603.19340](https://arxiv.org/pdf/2603.19340)).

La observación empírica encaja con la advertencia de `@noble/post-quantum`: la implementación en JavaScript no pretende ejecución en tiempo constante; el coste de firmar es variable y mayor que el de verificar.

#### Impacto en cómputo serverless

El wall-time del suite ACVP agrega muchos vectores y **no** equivale al coste de una sola operación. Para valorar firma de tokens en edge/serverless (p. ej. Vercel o Cloudflare Workers), medir ms/op individuales:

```bash
bun run bench:pq
```

Salida de referencia (media de 50 ops, máquina local):

| Operación | ms/op |
|-----------|------:|
| ML-KEM-768 keygen | ~1.0 |
| ML-KEM-768 encapsulate | ~1.1 |
| ML-KEM-768 decapsulate | ~1.3 |
| ML-DSA-65 keygen | ~3.3 |
| ML-DSA-65 sign | ~24.6 |
| ML-DSA-65 verify | ~3.9 |

Una sola firma ML-DSA-65 (~25 ms en este entorno) es el dato relevante frente al presupuesto de CPU de un plan gratuito serverless; el ~523 ms de `sigGen` ACVP corresponde a 30 vectores, no a una operación aislada.

Salida de referencia de la suite:

```
bun test v1.3.14

test\acvp-kat.test.js:
(pass) NIST ACVP KAT — ML-KEM-768 (FIPS 203) > keyGen
(pass) NIST ACVP KAT — ML-KEM-768 (FIPS 203) > encapDecap
(pass) NIST ACVP KAT — ML-DSA-65 (FIPS 204) > keyGen
(pass) NIST ACVP KAT — ML-DSA-65 (FIPS 204) > sigGen
(pass) NIST ACVP KAT — ML-DSA-65 (FIPS 204) > sigVer
(pass) Propiedades de rechazo (además de ACVP) > ML-DSA-65: firma corrompida (1 bit) → verify false
(pass) Propiedades de rechazo (además de ACVP) > ML-KEM-768: ciphertext corrompido → rechazo implícito

 7 pass
 0 fail
 358 expect() calls
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

Microbenchmark PQC:

```bash
bun run bench:pq
```

Consultar también `examples/ml-kem.js`, `examples/ml-dsa.js` y `examples/bench-pq.js`.

### Contexto

Un ordenador cuántico con el **algoritmo de Shor** podría romper RSA. **ML-KEM-768** y **ML-DSA-65** se diseñaron para resistir dicho escenario (NIST nivel 3 ≈ AES-192).