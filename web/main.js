import { classicalKeyExchange, classicalSignVerify } from './crypto/classical.js';
import { pqKeyExchange, pqSignVerify } from './crypto/pq.js';
import { fingerprint, sleep } from './crypto/util.js';

const state = {
  kem: 'classical',
  sig: 'classical'
};

/** Sesiones paso a paso */
const kemRun = { result: null, step: 0, busy: false };
const sigRun = { result: null, step: 0, busy: false, message: '' };

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function setText(sel, value) {
  const el = $(sel);
  if (el) el.textContent = value;
}

function showPreview(sel, bytes) {
  const el = $(sel);
  if (!el) return;
  if (!bytes || bytes.length === 0) {
    el.textContent = '-';
    return;
  }
  el.textContent = fingerprint(bytes);
}

/** Marca un valor como generado al azar por el algoritmo (no escrito a mano). */
function revealGenerated(tokenName, { preview, size, origin }, bytes) {
  activateToken(tokenName);
  const token = $(`[data-token="${tokenName}"]`);
  token?.classList.add('is-generated');
  showPreview(preview, bytes);
  if (size) setText(size, `${bytes.length} bytes`);
  if (origin) setText(origin, 'Generado automáticamente · aleatorio');
}

function activateToken(name) {
  const el = $(`[data-token="${name}"]`);
  if (!el) return;
  el.classList.remove('muted', 'is-unused');
  el.classList.add('is-live');
}

function muteAllTokens(scope) {
  $$(`${scope} [data-token]`).forEach((el) => {
    el.classList.add('muted');
    el.classList.remove('is-live', 'is-unused', 'is-generated');
  });
}

function markUnused(name) {
  const el = $(`[data-token="${name}"]`);
  if (!el) return;
  el.classList.add('is-unused');
  el.classList.remove('muted', 'is-live');
}

async function animatePacket(selector) {
  const packet = $(selector);
  if (!packet) return;
  packet.classList.remove('is-moving');
  void packet.offsetWidth;
  packet.classList.add('is-moving');
  await sleep(1100);
}

function formatGuideDetail(detail) {
  // Tras cada ". " (punto y aparte) → salto de línea
  return String(detail).replace(/\. +/g, '.<br>');
}

function renderSteps(containerSel, steps, activeIndex = -1) {
  const root = $(containerSel);
  if (!root) return;
  root.innerHTML = steps
    .map(
      (step, i) => `
      <li class="guide-item ${i === activeIndex ? 'is-active' : ''} ${i < activeIndex ? 'is-done' : ''}">
        <span class="guide-num">${i < activeIndex ? '✓' : i + 1}</span>
        <div>
          <strong>${step.title}</strong>
          <p>${formatGuideDetail(step.detail)}</p>
        </div>
      </li>`
    )
    .join('');
}

function renderBars(containerSel, items) {
  const root = $(containerSel);
  if (!root) return;
  const max = Math.max(...items.map((i) => i.bytes), 1);
  root.innerHTML = items
    .map(
      (item) => `
      <div class="bar-row">
        <span class="bar-label">${item.label}</span>
        <div class="bar-track">
          <div class="bar-fill ${item.tone || ''}" style="width:${Math.max(6, (item.bytes / max) * 100)}%"></div>
        </div>
        <span class="bar-value">${item.bytes} B</span>
      </div>`
    )
    .join('');
}

const KEM_SCRIPTS = {
  classical: {
    title: 'RSA-OAEP 2048 (clásico) — no es ML-KEM',
    hint: 'A la izquierda la guía. A la derecha la demo. Compara con ML-KEM-768: mismo guion, otro algoritmo.',
    roles: {
      alice: 'Dueña del par RSA · descifra',
      bob: 'Cifra con RSA-OAEP · sin par propio'
    },
    steps: [
      {
        title: 'Alice genera un par RSA-2048',
        detail:
          'Algoritmo clásico (factorización). Clave Pública (PK) + Clave Secreta (SK) RSA. No es ML-KEM: otra matemática.'
      },
      {
        title: 'Alice publica solo su clave pública RSA',
        detail:
          'Bob recibe la Clave Pública (PK). La Clave Secreta (SK) no viaja. Un QC con Shor podría, en el futuro, romper esta PK.'
      },
      {
        title: 'Bob cifra 32 bytes con RSA-OAEP',
        detail:
          'Bob elige el secreto al azar y lo cifra con la Clave Pública (PK) de Alice → ciphertext (~256 B). Bob no crea par propio.'
      },
      {
        title: 'Alice descifra con su secreta RSA',
        detail:
          'Obtiene los mismos 32 B. Mismo resultado que un KEM, pero el motor es RSA-OAEP (vulnerable a Shor).'
      }
    ]
  },
  pq: {
    title: 'ML-KEM-768 (post-cuántico) — no es RSA',
    hint: 'A la izquierda la guía. A la derecha la demo. Compara tamaños con RSA-OAEP: se ve que es otro algoritmo.',
    roles: {
      alice: 'Dueña del par ML-KEM · desencapsula',
      bob: 'Encapsula ML-KEM · sin par propio'
    },
    steps: [
      {
        title: 'Alice genera un par ML-KEM-768',
        detail:
          'FIPS 203, retículos (Module-LWE). Clave Pública (PK) ~1184 B. Clave Secreta (SK) ~2400 B. NIST nivel 3 (~AES-192).'
      },
      {
        title: 'Alice publica su clave pública ML-KEM',
        detail:
          'Bob recibe la Clave Pública (PK). La Clave Secreta (SK) no viaja. A diferencia de RSA, Shor no rompe esta base matemática.'
      },
      {
        title: 'Bob encapsula (secreto + ciphertext)',
        detail:
          'ML-KEM genera el secreto y el ciphertext a la vez (~1088 B). No es “cifrar con RSA”: es encapsulación en retículos.'
      },
      {
        title: 'Alice desencapsula → mismos 32 bytes',
        detail:
          'Mismo papel que RSA-OAEP en la demo, algoritmo distinto: resistente a Shor, ciphertext más grande.'
      }
    ]
  }
};

const SIG_SCRIPTS = {
  classical: {
    title: 'RSA-PSS 2048 (clásico) — no es ML-DSA',
    hint: 'A la izquierda la guía. A la derecha la demo. Compara con ML-DSA-65: misma idea, otra firma.',
    steps: [
      {
        title: 'Alice genera un par RSA-2048',
        detail:
          'Firma clásica RSA-PSS. Clave Pública (PK) + Clave Secreta (SK). Misma familia que RSA-OAEP; Shor también la amenaza.'
      },
      {
        title: 'Alice firma el mensaje con RSA-PSS',
        detail:
          'La firma (~256 B) sale de mensaje + Clave Secreta (SK). No se inventa a mano.'
      },
      {
        title: 'Viajan mensaje + firma (+ pública)',
        detail:
          'La Clave Secreta (SK) no viaja. Cualquiera puede ver el paquete; solo quien tiene la Clave Pública (PK) verifica.'
      },
      {
        title: 'Bob verifica con la pública RSA',
        detail:
          'Si el mensaje se altera, falla. Flujo igual que ML-DSA; algoritmo y tamaño distintos.'
      }
    ]
  },
  pq: {
    title: 'ML-DSA-65 (post-cuántico) — no es RSA-PSS',
    hint: 'A la izquierda la guía. A la derecha la demo. Mira el tamaño de la firma frente a RSA-PSS.',
    steps: [
      {
        title: 'Alice genera un par ML-DSA-65',
        detail:
          'FIPS 204, retículos. Pareja de ML-KEM-768 (NIST nivel 3). Claves más grandes que RSA-PSS.'
      },
      {
        title: 'Alice firma con ML-DSA-65',
        detail:
          'Firma ~3309 B (mucho mayor que RSA ~256 B). Mismo concepto “firmar”, otro algoritmo.'
      },
      {
        title: 'Viajan mensaje + firma',
        detail:
          'La Clave Secreta (SK) se queda en Alice. El paquete público es más pesado que con RSA-PSS.'
      },
      {
        title: 'Bob verifica con la pública ML-DSA',
        detail:
          'Misma comprobación que RSA-PSS. Diferencia clave: resiste Shor (NIST nivel 3 ≈ AES-192).'
      }
    ]
  }
};

/* ---------- Mode toggles ---------- */

document.querySelectorAll('.mode-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    const panel = btn.dataset.panel;
    const mode = btn.dataset.mode;
    state[panel] = mode;
    document
      .querySelectorAll(`.mode-btn[data-panel="${panel}"]`)
      .forEach((b) => b.classList.toggle('is-active', b === btn));
    if (panel === 'kem') resetKemUi();
    if (panel === 'sig') resetSigUi();
  });
});

/* ---------- KEM ---------- */

function resetKemUi() {
  const script = KEM_SCRIPTS[state.kem];
  kemRun.result = null;
  kemRun.step = 0;
  kemRun.busy = false;

  setText('[data-kem-guide-title]', script.title);
  setText('[data-role-alice]', script.roles.alice);
  setText('[data-role-bob]', script.roles.bob);
  setText('[data-kem-hint]', script.hint);
  renderSteps('[data-kem-steps]', script.steps, -1);
  muteAllTokens('[data-stage="kem"]');

  ['alice-pk', 'alice-sk', 'alice-ss', 'bob-pk', 'bob-sk', 'bob-ss'].forEach((k) => {
    setText(`[data-${k}]`, '-');
    setText(`[data-${k}-size]`, '-');
    setText(`[data-${k}-origin]`, k.endsWith('ss') ? 'Aún no generado' : 'Aún no generada');
  });

  // RSA-OAEP y ML-KEM: solo Alice tiene par; Bob no genera claves propias
  markUnused('bob-pk');
  markUnused('bob-sk');
  setText('[data-bob-pk]', '-');
  setText('[data-bob-sk]', '-');
  setText('[data-bob-pk-size]', '0 bytes');
  setText('[data-bob-sk-size]', '0 bytes');
  setText(
    '[data-bob-pk-origin]',
    state.kem === 'pq' ? 'No se genera en ML-KEM-768' : 'No se genera en RSA-OAEP'
  );
  setText(
    '[data-bob-sk-origin]',
    state.kem === 'pq' ? 'No se genera en ML-KEM-768' : 'No se genera en RSA-OAEP'
  );

  setText('[data-wire-label]', 'Nada en tránsito');
  setText('[data-wire-value]', '-');
  setText(
    '[data-wire-explain]',
    state.kem === 'pq'
      ? 'ML-KEM-768: viaja ciphertext de retículos (~1088 B), no el secreto. No es RSA.'
      : 'RSA-OAEP: viaja ciphertext RSA (~256 B), no el secreto. Vulnerable a Shor a futuro.'
  );

  $('[data-kem-sizes]').hidden = true;
  const banner = $('[data-kem-result]');
  banner.hidden = true;
  banner.classList.remove('is-warn');

  $('#kem-next').disabled = false;
  $('#kem-next').textContent = 'Siguiente paso';
  $('#kem-all').disabled = false;
}

async function ensureKemResult() {
  if (kemRun.result) return kemRun.result;
  setText('[data-kem-hint]', 'Generando material criptográfico…');
  kemRun.result =
    state.kem === 'pq' ? await pqKeyExchange() : await classicalKeyExchange();
  return kemRun.result;
}

async function applyKemStep(index) {
  const script = KEM_SCRIPTS[state.kem];
  const isPq = state.kem === 'pq';
  const result = await ensureKemResult();
  renderSteps('[data-kem-steps]', script.steps, index);

  if (index === 0) {
    setText('[data-kem-hint]', 'El algoritmo está generando el par de Alice al azar…');
    await sleep(350);
    revealGenerated(
      'alice-pk',
      {
        preview: '[data-alice-pk]',
        size: '[data-alice-pk-size]',
        origin: '[data-alice-pk-origin]'
      },
      result.alice.publicKey
    );
    revealGenerated(
      'alice-sk',
      {
        preview: '[data-alice-sk]',
        size: '[data-alice-sk-size]',
        origin: '[data-alice-sk-origin]'
      },
      result.alice.secretKey
    );
    setText(
      '[data-kem-hint]',
      'Paso 1/4: públicas y secretas de Alice = generadas al azar. Pulsa para el paso 2.'
    );
  }

  if (index === 1) {
    setText('[data-wire-label]', 'Viaja: clave pública de Alice (ya generada)');
    showPreview('[data-wire-value]', result.alice.publicKey);
    setText(
      '[data-wire-explain]',
      'Bob recibe bytes de la Clave Pública (PK) de Alice. Aún no hay secreto compartido.'
    );
    await animatePacket('[data-packet-kem]');
    setText('[data-kem-hint]', 'Paso 2/4 listo. Siguiente: Bob cifra / encapsula.');
  }

  if (index === 2) {
    setText('[data-wire-label]', `Viaja: ${result.wire.label}`);
    showPreview('[data-wire-value]', result.wire.value);
    setText(
      '[data-wire-explain]',
      isPq
        ? 'ML-KEM-768 encapsula: secreto + ciphertext de retículos (~1088 B). No es cifrado RSA.'
        : 'RSA-OAEP cifra 32 bytes con la Clave Pública (PK) RSA (~256 B de ciphertext). Motor distinto a ML-KEM.'
    );
    revealGenerated(
      'bob-ss',
      {
        preview: '[data-bob-ss]',
        size: '[data-bob-ss-size]',
        origin: '[data-bob-ss-origin]'
      },
      result.bob.sharedSecret
    );
    await animatePacket('[data-packet-kem]');
    setText('[data-kem-hint]', 'Paso 3/4 listo. Último: Alice abre el ciphertext.');
  }

  if (index === 3) {
    revealGenerated(
      'alice-ss',
      {
        preview: '[data-alice-ss]',
        size: '[data-alice-ss-size]',
        origin: '[data-alice-ss-origin]'
      },
      result.alice.sharedSecret
    );
    revealGenerated(
      'bob-ss',
      {
        preview: '[data-bob-ss]',
        size: '[data-bob-ss-size]',
        origin: '[data-bob-ss-origin]'
      },
      result.bob.sharedSecret
    );
    setText(
      '[data-alice-ss-origin]',
      isPq ? 'Desencapsulado por el algoritmo' : 'Descifrado por el algoritmo'
    );
    setText(
      '[data-bob-ss-origin]',
      isPq ? 'Encapsulado por el algoritmo' : 'Generado y cifrado por Bob'
    );

    const sizes = [
      { label: 'Clave Pública (PK)', bytes: result.sizes.publicKey, tone: 'tone-pub' },
      { label: 'Clave Secreta (SK)', bytes: result.sizes.secretKey, tone: 'tone-sec' },
      { label: 'Ciphertext', bytes: result.sizes.wire, tone: 'tone-wire' },
      { label: 'Secreto', bytes: result.sizes.sharedSecret, tone: 'tone-shared' }
    ];
    renderBars('[data-kem-bars]', sizes);
    $('[data-kem-sizes]').hidden = false;

    const banner = $('[data-kem-result]');
    banner.hidden = false;
    banner.classList.toggle('is-warn', !result.quantumSafe);
    $('[data-kem-result-text]').textContent = result.match
      ? result.quantumSafe
        ? `✓ Secretos iguales · ${result.algorithm} (NIST ${result.nistLevel}). Todo el material salió generado por el algoritmo.`
        : `✓ Secretos iguales · ${result.algorithm}. Claves generadas al azar. Shor podría romper RSA.`
      : 'Los secretos no coinciden.';

    setText('[data-kem-hint]', 'Demo terminada. Reinicia y verás otros valores aleatorios.');
    $('#kem-next').textContent = 'Hecho';
    $('#kem-next').disabled = true;
  }

  kemRun.step = index + 1;
}

async function kemNext() {
  if (kemRun.busy) return;
  if (kemRun.step >= 4) return;
  kemRun.busy = true;
  $('#kem-next').disabled = true;
  $('#kem-all').disabled = true;
  try {
    await applyKemStep(kemRun.step);
  } catch (err) {
    console.error(err);
    $('[data-kem-result]').hidden = false;
    $('[data-kem-result]').classList.add('is-warn');
    $('[data-kem-result-text]').textContent = `Error: ${err.message || err}`;
  } finally {
    kemRun.busy = false;
    if (kemRun.step < 4) {
      $('#kem-next').disabled = false;
      $('#kem-all').disabled = false;
    }
  }
}

async function kemAll() {
  if (kemRun.busy) return;
  resetKemUi();
  kemRun.busy = true;
  $('#kem-next').disabled = true;
  $('#kem-all').disabled = true;
  try {
    for (let i = 0; i < 4; i++) {
      await applyKemStep(i);
      if (i < 3) await sleep(550);
    }
  } catch (err) {
    console.error(err);
    $('[data-kem-result]').hidden = false;
    $('[data-kem-result]').classList.add('is-warn');
    $('[data-kem-result-text]').textContent = `Error: ${err.message || err}`;
  } finally {
    kemRun.busy = false;
  }
}

$('#kem-next').addEventListener('click', kemNext);
$('#kem-all').addEventListener('click', kemAll);
$('#kem-reset').addEventListener('click', resetKemUi);

/* ---------- Signatures ---------- */

function resetSigUi() {
  const script = SIG_SCRIPTS[state.sig];
  sigRun.result = null;
  sigRun.step = 0;
  sigRun.busy = false;
  sigRun.message = '';

  setText('[data-sig-guide-title]', script.title);
  setText('[data-sig-hint]', script.hint);
  renderSteps('[data-sig-steps]', script.steps, -1);
  muteAllTokens('[data-stage="sig"]');

  setText('[data-sig-alice-pk]', '-');
  setText('[data-sig-alice-sk]', '-');
  setText('[data-sig-value]', '-');
  setText('[data-sig-pk-size]', '-');
  setText('[data-sig-sk-size]', '-');
  setText('[data-sig-sig-size]', '-');
  setText('[data-sig-pk-origin]', 'Aún no generada');
  setText('[data-sig-sk-origin]', 'Aún no generada');
  setText('[data-sig-sig-origin]', 'Aún no generada');
  setText('[data-sig-verify]', '-');
  setText('[data-sig-tamper]', '-');
  $('[data-sig-verify]')?.classList.remove('ok', 'bad');
  $('[data-sig-tamper]')?.classList.remove('ok', 'bad');

  setText('[data-sig-wire-label]', 'Nada en tránsito');
  setText('[data-sig-wire-value]', '-');
  setText('[data-sig-wire-explain]', 'Mensaje + firma (+ pública). La secreta no viaja.');

  $('[data-sig-sizes]').hidden = true;
  const banner = $('[data-sig-result]');
  banner.hidden = true;
  banner.classList.remove('is-warn');

  $('#sig-next').disabled = false;
  $('#sig-next').textContent = 'Siguiente paso';
  $('#sig-all').disabled = false;
}

async function ensureSigResult() {
  if (sigRun.result) return sigRun.result;
  const message = $('#sig-message').value;
  sigRun.message = message;
  const bytes = new TextEncoder().encode(message);
  setText('[data-sig-hint]', 'Firmando…');
  sigRun.result =
    state.sig === 'pq' ? await pqSignVerify(bytes) : await classicalSignVerify(bytes);
  return sigRun.result;
}

async function applySigStep(index) {
  const script = SIG_SCRIPTS[state.sig];
  const result = await ensureSigResult();
  const message = sigRun.message;
  renderSteps('[data-sig-steps]', script.steps, index);

  if (index === 0) {
    setText('[data-sig-hint]', 'El algoritmo genera el par de Alice al azar…');
    await sleep(350);
    revealGenerated(
      'sig-pk',
      {
        preview: '[data-sig-alice-pk]',
        size: '[data-sig-pk-size]',
        origin: '[data-sig-pk-origin]'
      },
      result.publicKey
    );
    revealGenerated(
      'sig-sk',
      {
        preview: '[data-sig-alice-sk]',
        size: '[data-sig-sk-size]',
        origin: '[data-sig-sk-origin]'
      },
      result.secretKey
    );
    setText('[data-sig-hint]', 'Paso 1/4: par generado automáticamente. Siguiente: firmar.');
  }

  if (index === 1) {
    setText('[data-sig-hint]', 'El algoritmo calcula la firma a partir del mensaje + secreta…');
    await sleep(350);
    revealGenerated(
      'sig-sig',
      {
        preview: '[data-sig-value]',
        size: '[data-sig-sig-size]',
        origin: '[data-sig-sig-origin]'
      },
      result.signature
    );
    setText('[data-sig-sig-origin]', 'Calculada por el algoritmo (no a mano)');
    setText('[data-sig-hint]', 'Paso 2/4. Siguiente: enviar por el canal.');
  }

  if (index === 2) {
    setText('[data-sig-wire-label]', 'Viaja: mensaje + firma (+ pública)');
    const short = message.length > 36 ? `${message.slice(0, 36)}…` : message;
    setText(
      '[data-sig-wire-value]',
      `"${short}" + firma ${fingerprint(result.signature)}`
    );
    setText(
      '[data-sig-wire-explain]',
      state.sig === 'pq'
        ? `ML-DSA-65: firma ${result.signature.length} B (retículos). No es RSA-PSS.`
        : `RSA-PSS: firma ${result.signature.length} B. Misma familia RSA; Shor la amenaza a futuro.`
    );
    await animatePacket('[data-packet-sig]');
    setText('[data-sig-hint]', 'Paso 3/4. Siguiente: verificar.');
  }

  if (index === 3) {
    activateToken('sig-verify');
    activateToken('sig-tamper');
    const verifyEl = $('[data-sig-verify]');
    const tamperEl = $('[data-sig-tamper]');
    verifyEl.textContent = result.valid ? 'VÁLIDA - es de Alice' : 'INVÁLIDA';
    verifyEl.classList.toggle('ok', result.valid);
    verifyEl.classList.toggle('bad', !result.valid);
    tamperEl.textContent = result.tamperedValid
      ? 'VÁLIDA (error)'
      : 'INVÁLIDA - manipulación detectada';
    tamperEl.classList.toggle('ok', !result.tamperedValid);
    tamperEl.classList.toggle('bad', result.tamperedValid);

    renderBars('[data-sig-bars]', [
      { label: 'Clave Pública (PK)', bytes: result.sizes.publicKey, tone: 'tone-pub' },
      { label: 'Clave Secreta (SK)', bytes: result.sizes.secretKey, tone: 'tone-sec' },
      { label: 'Firma', bytes: result.sizes.signature, tone: 'tone-wire' }
    ]);
    $('[data-sig-sizes]').hidden = false;

    const banner = $('[data-sig-result]');
    banner.hidden = false;
    banner.classList.toggle('is-warn', !result.quantumSafe);
    $('[data-sig-result-text]').textContent = result.quantumSafe
      ? `✓ ${result.algorithm} (NIST ${result.nistLevel}): mismo flujo, firma ${result.sizes.signature} B.`
      : `✓ ${result.algorithm}: firma ${result.sizes.signature} B. Shor podría falsificar RSA.`;

    setText('[data-sig-hint]', 'Demo terminada. Cambia modo o reinicia.');
    $('#sig-next').textContent = 'Hecho';
    $('#sig-next').disabled = true;
  }

  sigRun.step = index + 1;
}

async function sigNext() {
  if (sigRun.busy || sigRun.step >= 4) return;
  sigRun.busy = true;
  $('#sig-next').disabled = true;
  $('#sig-all').disabled = true;
  try {
    await applySigStep(sigRun.step);
  } catch (err) {
    console.error(err);
    $('[data-sig-result]').hidden = false;
    $('[data-sig-result]').classList.add('is-warn');
    $('[data-sig-result-text]').textContent = `Error: ${err.message || err}`;
  } finally {
    sigRun.busy = false;
    if (sigRun.step < 4) {
      $('#sig-next').disabled = false;
      $('#sig-all').disabled = false;
    }
  }
}

async function sigAll() {
  if (sigRun.busy) return;
  resetSigUi();
  sigRun.busy = true;
  $('#sig-next').disabled = true;
  $('#sig-all').disabled = true;
  try {
    for (let i = 0; i < 4; i++) {
      await applySigStep(i);
      if (i < 3) await sleep(550);
    }
  } catch (err) {
    console.error(err);
    $('[data-sig-result]').hidden = false;
    $('[data-sig-result]').classList.add('is-warn');
    $('[data-sig-result-text]').textContent = `Error: ${err.message || err}`;
  } finally {
    sigRun.busy = false;
  }
}

$('#sig-next').addEventListener('click', sigNext);
$('#sig-all').addEventListener('click', sigAll);
$('#sig-reset').addEventListener('click', resetSigUi);

resetKemUi();
resetSigUi();
