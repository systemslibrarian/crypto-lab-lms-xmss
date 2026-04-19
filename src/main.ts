import './style.css';
import { bytesToHex, textEncoder } from './bytes';
import { LMS_PARAMS, lmsKeygen, lmsSign, lmsVerify, signaturesRemaining } from './lms';
import type { LMSPrivateKey, LMSPublicKey } from './lms';
import { hssKeygen, hssSign, hssVerify } from './hss';
import type { HSSPrivateKey, HSSPublicKey } from './hss';

const APP = document.querySelector<HTMLDivElement>('#app');
if (!APP) {
  throw new Error('Missing #app container');
}

const LEAF_COUNT = 1 << LMS_PARAMS.h;

let lmsPrivateKey: LMSPrivateKey | null = null;
let lmsPublicKey: LMSPublicKey | null = null;
let lmsStorageKey: string | null = null;
let lastLmsSignature: Uint8Array | null = null;
let lastLmsQ: number | null = null;

let hssPrivateKey: HSSPrivateKey | null = null;
let hssPublicKey: HSSPublicKey | null = null;
let lastHssSignature: Uint8Array | null = null;

function shortHex(data: Uint8Array, chars = 16): string {
  const hex = bytesToHex(data);
  return `${hex.slice(0, chars)}...`;
}

function keyId(pub: LMSPublicKey): string {
  return `${bytesToHex(pub.I)}:${bytesToHex(pub.T1).slice(0, 24)}`;
}

function usedKeyStorageName(id: string): string {
  return `lms-used-${id}`;
}

function readStoredUsedIndexes(): Set<number> {
  if (!lmsStorageKey) {
    return new Set<number>();
  }
  const raw = localStorage.getItem(usedKeyStorageName(lmsStorageKey));
  if (!raw) {
    return new Set<number>();
  }

  try {
    const parsed = JSON.parse(raw) as number[];
    return new Set<number>(parsed.filter((n) => Number.isInteger(n) && n >= 0 && n < LEAF_COUNT));
  } catch {
    return new Set<number>();
  }
}

function persistUsedIndexes(): void {
  if (!lmsPrivateKey || !lmsStorageKey) {
    return;
  }
  const used = [...lmsPrivateKey.usedIndexes].sort((a, b) => a - b);
  localStorage.setItem(usedKeyStorageName(lmsStorageKey), JSON.stringify(used));
}

function setButtonBusy(btn: HTMLButtonElement | null, busy: boolean, label?: string): void {
  if (!btn) return;
  btn.disabled = busy;
  if (label) btn.textContent = busy ? label : btn.dataset.originalLabel ?? btn.textContent ?? '';
  if (!btn.dataset.originalLabel && busy && label) btn.dataset.originalLabel = btn.textContent ?? '';
  if (!busy) delete btn.dataset.originalLabel;
}

function setupLayout(): void {
  const app = APP as HTMLDivElement;
  app.innerHTML = `
    <a href="#main-content" class="skip-nav">Skip to main content</a>
    <div class="shell">
      <header class="hero">
        <p class="kicker">Crypto Lab • Stateful Hash-Based Signatures</p>
        <h1>LMS + HSS Vault</h1>
        <p class="lead">Every signature burns one slot forever. Reuse one index once and trust is gone.</p>
      </header>

      <main class="grid" id="main-content">
        <section class="panel" id="exhibit-1" aria-labelledby="h2-ex1">
          <h2 id="h2-ex1">Exhibit 1: Merkle Tree of OTS Keys</h2>
          <p class="muted">Generate LMS_SHA256_M32_H10 (1024 signatures) and inspect each leaf state.</p>
          <div class="controls">
            <button id="btn-lms-keygen">Generate LMS Keypair</button>
            <span id="lms-progress" class="mono" role="status" aria-live="polite" aria-label="LMS keygen progress">Idle</span>
          </div>
          <div id="lms-pk" class="kv" aria-live="polite"></div>
          <div id="lms-meter" class="meter" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" aria-label="Signatures used"></div>
          <div id="leaf-info" class="note" role="status" aria-live="polite">Click a leaf square to inspect its status.</div>
          <div id="leaf-grid" class="leaf-grid" role="grid" aria-label="LMS leaf key grid"></div>
        </section>

        <section class="panel" id="exhibit-2" aria-labelledby="h2-ex2">
          <h2 id="h2-ex2">Exhibit 2: Signing Consumes State</h2>
          <p class="muted">State is enforced with localStorage used-index tracking and q monotonic updates.</p>
          <div class="controls stacked">
            <label for="lms-message">Message</label>
            <input id="lms-message" value="Firmware v2.3.1 release" aria-describedby="lms-sign-status" />
            <div class="row">
              <button id="btn-lms-sign">Sign Message</button>
              <button id="btn-lms-sign-again">Sign Again</button>
            </div>
            <label for="q-override">Unsafe manual q override (demo corruption)</label>
            <input id="q-override" type="number" min="0" max="1023" value="0" aria-describedby="lms-sign-status" />
            <button id="btn-q-override" class="warn">Set q Unsafely</button>
          </div>
          <div id="lms-sign-status" class="note" role="status" aria-live="polite"></div>
          <div id="lms-signature" class="mono sig" aria-label="LMS signature bytes"></div>
          <div class="danger">
            <h3>Danger Zone</h3>
            <p>Exporting and reusing private state can trigger catastrophic index reuse.</p>
            <button id="btn-export-state" class="danger-btn">Export Secret State (Unsafe)</button>
            <textarea id="export-box" readonly placeholder="Unsafe export appears here" aria-label="Exported private state — unsafe"></textarea>
          </div>
        </section>

        <section class="panel" id="exhibit-3" aria-labelledby="h2-ex3">
          <h2 id="h2-ex3">Exhibit 3: Authentication Path Walk</h2>
          <p class="muted">Each LMS signature carries 10 sibling hashes to rebuild the root.</p>
          <ol id="auth-steps" class="steps" aria-live="polite"></ol>
        </section>

        <section class="panel" id="exhibit-4" aria-labelledby="h2-ex4">
          <h2 id="h2-ex4">Exhibit 4: HSS Hierarchy</h2>
          <p class="muted">Root H=5 signs leaf-tree public keys; each leaf tree signs up to 1024 messages.</p>
          <div class="controls stacked">
            <button id="btn-hss-keygen">Generate HSS Keypair</button>
            <span id="hss-progress" class="mono" role="status" aria-live="polite" aria-label="HSS keygen progress">Idle</span>
            <label for="hss-message">Message</label>
            <input id="hss-message" value="Signed boot manifest" />
            <button id="btn-hss-sign">Sign with HSS</button>
          </div>
          <div id="hss-state" class="kv" aria-live="polite"></div>
          <div id="hss-sig" class="mono sig" role="status" aria-live="polite" aria-label="HSS signature result"></div>
        </section>

        <section class="panel" id="exhibit-5" aria-labelledby="h2-ex5">
          <h2 id="h2-ex5">Exhibit 5: When Stateful Signatures Win</h2>
          <div class="decision mono">
            Need PQ signatures?
            Yes -> Need unlimited signatures?
            Yes -> Use SLH-DSA (stateless)
            No -> Can you manage state reliably?
            Yes -> LMS/XMSS (small signatures)
            No -> Use stateless schemes
          </div>
          <ul class="bullets">
            <li>Best fit: firmware, boot chains, root code-signing ceremonies, HSM-bound flows.</li>
            <li>Avoid for general web signatures and distributed unconstrained signers.</li>
            <li>Real deployments: Cisco firmware, AWS Nitro paths, TPM 2.0 optional support.</li>
          </ul>
          <p class="muted">Cross-labs: crypto-lab-sphincs-ledger, crypto-lab-dilithium-seal, crypto-lab-falcon-seal, crypto-lab-hybrid-sign.</p>
        </section>
      </main>
    </div>
  `;
}

function renderLmsPublic(): void {
  const target = document.querySelector<HTMLDivElement>('#lms-pk');
  if (!target) {
    return;
  }
  if (!lmsPublicKey || !lmsPrivateKey) {
    target.innerHTML = '<p class="muted">No LMS keypair generated yet.</p>';
    return;
  }

  const rem = signaturesRemaining(lmsPrivateKey);
  const pctUsed = ((LEAF_COUNT - rem) / LEAF_COUNT) * 100;
  const warningClass = rem === 0 ? 'critical' : rem < 103 ? 'amber' : 'ok';

  target.innerHTML = `
    <p><strong>I</strong> ${shortHex(lmsPublicKey.I, 20)}</p>
    <p><strong>T[1]</strong> ${shortHex(lmsPublicKey.T1, 24)}</p>
    <p><strong>q</strong> ${lmsPrivateKey.q}</p>
    <p class="${warningClass}"><strong>Signatures remaining</strong> ${rem} / ${LEAF_COUNT}</p>
    <p><strong>Used</strong> ${pctUsed.toFixed(2)}%</p>
  `;

  const meter = document.querySelector<HTMLDivElement>('#lms-meter');
  if (meter) {
    const pct = Math.min(100, Math.max(0, pctUsed));
    meter.setAttribute('aria-valuenow', String(Math.round(pct)));
    meter.innerHTML = `<div class="fill" style="width:${pct}%"></div>`;
  }
}

function renderLeafGrid(): void {
  const grid = document.querySelector<HTMLDivElement>('#leaf-grid');
  if (!grid) {
    return;
  }
  if (!lmsPrivateKey) {
    grid.innerHTML = '';
    return;
  }

  const used = lmsPrivateKey.usedIndexes;
  const current = lmsPrivateKey.q;
  const fragments: string[] = [];
  for (let i = 0; i < LEAF_COUNT; i += 1) {
    const usedClass = used.has(i) ? 'used' : 'fresh';
    const currentClass = i === current ? 'current' : '';
    const stateLabel = used.has(i) ? 'used' : i === current ? 'next signing index' : 'available';
    fragments.push(`<button class="leaf ${usedClass} ${currentClass}" data-leaf="${i}" aria-label="Leaf ${i}: ${stateLabel}" title="Leaf ${i}: ${stateLabel}">${i % 10}</button>`);
  }
  grid.innerHTML = fragments.join('');
}

function renderAuthPathDetails(): void {
  const steps = document.querySelector<HTMLOListElement>('#auth-steps');
  if (!steps) {
    return;
  }

  if (!lastLmsSignature || lastLmsQ === null) {
    steps.innerHTML = '<li>Create a signature first to view path reconstruction steps.</li>';
    return;
  }

  const auth: string[] = [];
  let offset = 4 + 1124 + 4;
  for (let i = 0; i < LMS_PARAMS.h; i += 1) {
    const h = lastLmsSignature.slice(offset, offset + 32);
    auth.push(bytesToHex(h));
    offset += 32;
  }

  const rows = [
    `<li>q = ${lastLmsQ}, compute LM-OTS public key candidate from signature + message.</li>`,
    ...auth.map((h, idx) => `<li>Level ${idx + 1}: combine node with sibling ${h.slice(0, 20)}...</li>`),
    '<li>Final computed root is compared against LMS public key T[1].</li>',
  ];
  steps.innerHTML = rows.join('');
}

function updateAllLmsViews(): void {
  renderLmsPublic();
  renderLeafGrid();
  renderAuthPathDetails();
}

async function handleLmsKeygen(): Promise<void> {
  const btn = document.querySelector<HTMLButtonElement>('#btn-lms-keygen');
  const progress = document.querySelector<HTMLSpanElement>('#lms-progress');
  setButtonBusy(btn, true, 'Generating...');
  if (progress) {
    progress.textContent = 'Generating 1024 leaves...';
  }

  try {
    const result = await lmsKeygen((computed, total) => {
      if (progress) {
        progress.textContent = `Leafs ${computed}/${total}`;
      }
    });

    lmsPrivateKey = result.privateKey;
    lmsPublicKey = result.publicKey;
    lmsStorageKey = keyId(result.publicKey);

    const stored = readStoredUsedIndexes();
    lmsPrivateKey.usedIndexes = stored;
    if (stored.size > 0) {
      lmsPrivateKey.q = Math.max(...stored) + 1;
    }

    persistUsedIndexes();
    if (progress) {
      progress.textContent = 'Ready';
    }
    updateAllLmsViews();
  } catch (err) {
    if (progress) {
      progress.textContent = 'Error - see console';
    }
    console.error(err);
  } finally {
    setButtonBusy(btn, false);
  }
}

async function handleLmsSign(repeatOnly = false): Promise<void> {
  const status = document.querySelector<HTMLDivElement>('#lms-sign-status');
  const sigBox = document.querySelector<HTMLDivElement>('#lms-signature');
  const input = document.querySelector<HTMLInputElement>('#lms-message');
  const btnSign = document.querySelector<HTMLButtonElement>('#btn-lms-sign');
  const btnAgain = document.querySelector<HTMLButtonElement>('#btn-lms-sign-again');
  if (!status || !sigBox || !input) {
    return;
  }

  if (!lmsPrivateKey || !lmsPublicKey) {
    status.textContent = 'Generate LMS keypair first.';
    return;
  }

  const q = lmsPrivateKey.q;
  const localUsed = readStoredUsedIndexes();
  if (localUsed.has(q)) {
    status.textContent = `ERROR: Index ${q} is already marked used in localStorage. Refusing to sign.`;
    status.className = 'note critical';
    return;
  }

  setButtonBusy(btnSign, true, 'Signing...');
  setButtonBusy(btnAgain, true, 'Signing...');
  try {
    const msgBytes = textEncoder.encode(input.value);
    const { signature, qUsed, remainingSignatures } = await lmsSign(msgBytes, lmsPrivateKey);
    const ok = await lmsVerify(msgBytes, signature, lmsPublicKey);
    lastLmsSignature = signature;
    lastLmsQ = qUsed;

    persistUsedIndexes();
    updateAllLmsViews();

    sigBox.textContent = `${signature.length} bytes\n${bytesToHex(signature).slice(0, 220)}...`;
    status.textContent = `Signed with q=${qUsed}. Verify=${ok ? 'valid' : 'invalid'}. Remaining=${remainingSignatures}.`;
    status.className = 'note ok';

    if (repeatOnly) {
      status.textContent += ' (Signed same message with next leaf as expected.)';
    }
  } catch (err) {
    status.textContent = err instanceof Error ? err.message : 'Unknown signing error.';
    status.className = 'note critical';
  } finally {
    setButtonBusy(btnSign, false);
    setButtonBusy(btnAgain, false);
  }
}

function handleLeafClick(event: Event): void {
  const target = event.target as HTMLElement;
  if (!target.classList.contains('leaf') || !lmsPrivateKey) {
    return;
  }
  const idx = Number(target.dataset.leaf ?? '-1');
  const info = document.querySelector<HTMLDivElement>('#leaf-info');
  if (!info || idx < 0) {
    return;
  }
  const used = lmsPrivateKey.usedIndexes.has(idx);
  info.textContent = `Leaf ${idx}: ${used ? 'USED (unsafe to reuse)' : 'available'}${idx === lmsPrivateKey.q ? ' • next signing index' : ''}`;
}

function handleUnsafeQOverride(): void {
  const input = document.querySelector<HTMLInputElement>('#q-override');
  const status = document.querySelector<HTMLDivElement>('#lms-sign-status');
  if (!input || !status || !lmsPrivateKey) {
    return;
  }
  lmsPrivateKey.q = Number.parseInt(input.value, 10);
  updateAllLmsViews();
  status.textContent = `q manually set to ${lmsPrivateKey.q}. This simulates state corruption risk.`;
  status.className = 'note amber';
}

function handleExportDanger(): void {
  const box = document.querySelector<HTMLTextAreaElement>('#export-box');
  if (!box || !lmsPrivateKey || !lmsPublicKey) {
    return;
  }

  const exported = {
    warning: 'Re-importing this state in another signer can cause index reuse and key compromise.',
    private: {
      I: bytesToHex(lmsPrivateKey.I),
      seed: bytesToHex(lmsPrivateKey.seed),
      q: lmsPrivateKey.q,
      usedIndexes: [...lmsPrivateKey.usedIndexes].sort((a, b) => a - b),
    },
    public: {
      I: bytesToHex(lmsPublicKey.I),
      T1: bytesToHex(lmsPublicKey.T1),
      typecode: lmsPublicKey.typecode,
      otsTypecode: lmsPublicKey.otsTypecode,
    },
  };

  box.value = JSON.stringify(exported, null, 2);
}

function renderHssState(): void {
  const state = document.querySelector<HTMLDivElement>('#hss-state');
  if (!state) {
    return;
  }
  if (!hssPrivateKey) {
    state.innerHTML = '<p class="muted">No HSS keypair generated yet.</p>';
    return;
  }

  const used = hssPrivateKey.levelUsed * 1024 + hssPrivateKey.activeLeafLMSKey.q;
  const remaining = 32768 - used;

  state.innerHTML = `
    <p><strong>Root q</strong> ${hssPrivateKey.rootLMSKey.q} / ${hssPrivateKey.rootLMSKey.maxQ}</p>
    <p><strong>Active leaf tree</strong> ${hssPrivateKey.levelUsed}</p>
    <p><strong>Leaf q</strong> ${hssPrivateKey.activeLeafLMSKey.q} / ${hssPrivateKey.activeLeafLMSKey.maxQ}</p>
    <p><strong>Total used</strong> ${used}</p>
    <p class="${remaining < 3000 ? 'amber' : 'ok'}"><strong>Total remaining</strong> ${remaining}</p>
  `;
}

async function handleHssKeygen(): Promise<void> {
  const btn = document.querySelector<HTMLButtonElement>('#btn-hss-keygen');
  const progress = document.querySelector<HTMLSpanElement>('#hss-progress');
  setButtonBusy(btn, true, 'Generating...');
  if (progress) {
    progress.textContent = 'Generating HSS trees...';
  }

  try {
    const result = await hssKeygen((stage, percent) => {
      if (progress) {
        progress.textContent = `${stage} ${Math.round(percent)}%`;
      }
    });

    hssPrivateKey = result.privateKey;
    hssPublicKey = result.publicKey;
    renderHssState();
    if (progress) {
      progress.textContent = 'Ready';
    }
  } catch (err) {
    if (progress) {
      progress.textContent = 'Error - see console';
    }
    console.error(err);
  } finally {
    setButtonBusy(btn, false);
  }
}

async function handleHssSign(): Promise<void> {
  const input = document.querySelector<HTMLInputElement>('#hss-message');
  const box = document.querySelector<HTMLDivElement>('#hss-sig');
  const btn = document.querySelector<HTMLButtonElement>('#btn-hss-sign');
  if (!input || !box || !hssPrivateKey || !hssPublicKey) {
    if (box) {
      box.textContent = 'Generate HSS keypair first.';
    }
    return;
  }

  setButtonBusy(btn, true, 'Signing...');
  try {
    const msg = textEncoder.encode(input.value);
    const signature = await hssSign(msg, hssPrivateKey);
    const ok = await hssVerify(msg, signature, hssPublicKey);
    lastHssSignature = signature;

    renderHssState();
    box.textContent = `${signature.length} bytes • verify=${ok ? 'valid' : 'invalid'}\n${bytesToHex(signature).slice(0, 220)}...`;
  } catch (err) {
    box.textContent = err instanceof Error ? err.message : 'Unknown signing error.';
    console.error(err);
  } finally {
    setButtonBusy(btn, false);
  }
}

function bindEvents(): void {
  const btnLmsKeygen = document.querySelector<HTMLButtonElement>('#btn-lms-keygen');
  const btnLmsSign = document.querySelector<HTMLButtonElement>('#btn-lms-sign');
  const btnLmsSignAgain = document.querySelector<HTMLButtonElement>('#btn-lms-sign-again');
  const btnUnsafeQ = document.querySelector<HTMLButtonElement>('#btn-q-override');
  const btnExport = document.querySelector<HTMLButtonElement>('#btn-export-state');
  const leafGrid = document.querySelector<HTMLDivElement>('#leaf-grid');
  const btnHssKeygen = document.querySelector<HTMLButtonElement>('#btn-hss-keygen');
  const btnHssSign = document.querySelector<HTMLButtonElement>('#btn-hss-sign');

  btnLmsKeygen?.addEventListener('click', () => {
    void handleLmsKeygen();
  });
  btnLmsSign?.addEventListener('click', () => {
    void handleLmsSign(false);
  });
  btnLmsSignAgain?.addEventListener('click', () => {
    void handleLmsSign(true);
  });
  btnUnsafeQ?.addEventListener('click', handleUnsafeQOverride);
  btnExport?.addEventListener('click', handleExportDanger);
  leafGrid?.addEventListener('click', handleLeafClick);
  btnHssKeygen?.addEventListener('click', () => {
    void handleHssKeygen();
  });
  btnHssSign?.addEventListener('click', () => {
    void handleHssSign();
  });
}

setupLayout();
bindEvents();
updateAllLmsViews();
renderHssState();

void lastHssSignature;
