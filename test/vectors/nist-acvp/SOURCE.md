# NIST ACVP vectors (filtered)

Este directorio contiene vectores ACVP filtrados a partir de la fuente oficial de NIST.
El alcance de la validación se describe en el [README](../../../README.md).

Fuente oficial: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

Commit pinneado (ruta `gen-val/json-files`): `a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324`

Filtro aplicado:
- Solo `ML-KEM-768` y `ML-DSA-65` (NIST nivel 3)
- ML-KEM encapDecap: únicamente `encapsulation` / `decapsulation` (sin key-check)
- ML-DSA sigGen/sigVer: únicamente `signatureInterface: external` y sin HashML-DSA (`preHash`)

Regenerar los fixtures:

```bash
bun run vectors:fetch
```

Suites incluidas:
- `ML-KEM-keyGen-FIPS203`: 1 grupos, 25 tests
- `ML-KEM-encapDecap-FIPS203`: 2 grupos, 35 tests
- `ML-DSA-keyGen-FIPS204`: 1 grupos, 25 tests
- `ML-DSA-sigGen-FIPS204`: 2 grupos, 30 tests
- `ML-DSA-sigVer-FIPS204`: 1 grupos, 15 tests
