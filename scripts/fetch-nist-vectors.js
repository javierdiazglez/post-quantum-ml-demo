/**
 * Descarga vectores ACVP oficiales de NIST y filtra a ML-KEM-768 / ML-DSA-65.
 * Fuente: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
 */
import { mkdir, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, '..', 'test', 'vectors', 'nist-acvp');
const RAW =
  'https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files';
const API =
  'https://api.github.com/repos/usnistgov/ACVP-Server/commits?path=gen-val/json-files&per_page=1';

const SUITES = [
  {
    name: 'ML-KEM-keyGen-FIPS203',
    keep: (g) => g.parameterSet === 'ML-KEM-768'
  },
  {
    name: 'ML-KEM-encapDecap-FIPS203',
    keep: (g) =>
      g.parameterSet === 'ML-KEM-768' &&
      (g.function === 'encapsulation' || g.function === 'decapsulation')
  },
  {
    name: 'ML-DSA-keyGen-FIPS204',
    keep: (g) => g.parameterSet === 'ML-DSA-65'
  },
  {
    name: 'ML-DSA-sigGen-FIPS204',
    keep: (g) =>
      g.parameterSet === 'ML-DSA-65' &&
      g.signatureInterface === 'external' &&
      g.preHash !== 'preHash'
  },
  {
    name: 'ML-DSA-sigVer-FIPS204',
    keep: (g) =>
      g.parameterSet === 'ML-DSA-65' &&
      g.signatureInterface === 'external' &&
      g.preHash !== 'preHash'
  }
];

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return res.json();
}

function filterSuite(prompt, expected, keep) {
  const promptGroups = [];
  const expectedGroups = [];

  for (let i = 0; i < prompt.testGroups.length; i++) {
    const pg = prompt.testGroups[i];
    const eg = expected.testGroups[i];
    if (!eg || eg.tgId !== pg.tgId) {
      throw new Error(`tgId mismatch in group index ${i} (${prompt.algorithm})`);
    }
    if (!keep(pg)) continue;

    const erByTc = new Map(eg.tests.map((t) => [t.tcId, t]));
    const testsP = [];
    const testsE = [];
    for (const t of pg.tests) {
      const er = erByTc.get(t.tcId);
      if (!er) throw new Error(`missing expected tcId ${t.tcId} in ${prompt.mode}`);
      testsP.push(t);
      testsE.push(er);
    }
    promptGroups.push({ ...pg, tests: testsP });
    expectedGroups.push({ ...eg, tests: testsE });
  }

  return {
    prompt: { ...prompt, testGroups: promptGroups },
    expectedResults: { ...expected, testGroups: expectedGroups }
  };
}

async function main() {
  await mkdir(OUT, { recursive: true });

  let commitSha = 'unknown';
  try {
    const commits = await fetchJson(API);
    commitSha = commits[0]?.sha ?? 'unknown';
  } catch {
    console.warn('No se pudo resolver el commit SHA de ACVP-Server; se usará "unknown".');
  }

  const summary = [];

  for (const suite of SUITES) {
    console.log(`Descargando ${suite.name}…`);
    const prompt = await fetchJson(`${RAW}/${suite.name}/prompt.json`);
    const expected = await fetchJson(`${RAW}/${suite.name}/expectedResults.json`);
    const filtered = filterSuite(prompt, expected, suite.keep);

    const nTests = filtered.prompt.testGroups.reduce((n, g) => n + g.tests.length, 0);
    console.log(`  → ${filtered.prompt.testGroups.length} grupos, ${nTests} tests`);

    const dir = join(OUT, suite.name);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'prompt.json'), JSON.stringify(filtered.prompt));
    await writeFile(join(dir, 'expectedResults.json'), JSON.stringify(filtered.expectedResults));
    summary.push({ name: suite.name, groups: filtered.prompt.testGroups.length, tests: nTests });
  }

  // Genera test/vectors/nist-acvp/SOURCE.md (provenance del filtro).
  await writeFile(join(OUT, 'SOURCE.md'), buildSourceMd(commitSha, summary));
  console.log('Listo →', OUT);
}

/** Markdown de provenance escrito junto a los JSON filtrados. */
function buildSourceMd(commitSha, summary) {
  const suiteLines = summary.map(
    (s) => `- \`${s.name}\`: ${s.groups} grupos, ${s.tests} tests`
  );
  return [
    '# NIST ACVP vectors (filtered)',
    '',
    'Este directorio contiene vectores ACVP filtrados a partir de la fuente oficial de NIST.',
    'El alcance de la validación se describe en el [README](../../../README.md).',
    '',
    'Fuente oficial: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files',
    '',
    `Commit pinneado (ruta gen-val/json-files): \`${commitSha}\``,
    '',
    'Filtro aplicado:',
    '- Solo `ML-KEM-768` y `ML-DSA-65` (NIST nivel 3)',
    '- ML-KEM encapDecap: únicamente `encapsulation` / `decapsulation` (sin key-check)',
    '- ML-DSA sigGen/sigVer: únicamente `signatureInterface: external` y sin HashML-DSA (`preHash`)',
    '',
    'Regenerar los fixtures:',
    '',
    '```bash',
    'bun run vectors:fetch',
    '```',
    '',
    'Suites incluidas:',
    ...suiteLines,
    ''
  ].join('\n');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
