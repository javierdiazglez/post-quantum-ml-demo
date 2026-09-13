# Post-Quantum ML Demo

## Algoritmos Post-Cuánticos Implementados

Demostración interactiva (Alice & Bob) de criptografía clásica frente a post-cuántica NIST nivel 3, usando `@noble/post-quantum`.

| Necesidad | Clásico (vulnerable a QC) | Post-cuántico |
|-----------|---------------------------|---------------|
| Intercambio / encapsular secreto | RSA-OAEP 2048 | **ML-KEM-768** (FIPS 203, NIST nivel 3) |
| Firmas digitales | RSA-PSS 2048 | **ML-DSA-65** (FIPS 204, NIST nivel 3) |

- **ML-KEM** (*Module-Lattice Key-Encapsulation Mechanism*; antes CRYSTALS-Kyber, FIPS 203) — encapsulación / intercambio de clave. En la demo: **ML-KEM-768** (NIST nivel 3).
- **ML-DSA** (*Module-Lattice Digital Signature Algorithm*; antes CRYSTALS-Dilithium, FIPS 204) — firmas digitales. En la demo: **ML-DSA-65** (NIST nivel 3).

### Requisitos

* Node.js **22+**

### Arrancar la web

```bash
npm install
npm run dev
```

### Ejemplos de código (CLI)

Referencia mínima de uso de cada algoritmo:

```bash
npm run demo:ml-kem
npm run demo:ml-dsa
```

Ver también `examples/ml-kem.js` y `examples/ml-dsa.js`.

### Idea

Un ordenador cuántico con el **algoritmo de Shor** podría romper RSA. **ML-KEM-768** y **ML-DSA-65** se diseñaron para resistir también ese escenario (NIST nivel 3 ≈ AES-192).

> Prototipo educativo. No usar para proteger datos reales sin auditoría.