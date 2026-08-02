import './style.css';
import { bytesToHex, concatBytes, randomBytes, textEncoder } from './bytes';
import {
  LMS_PARAMS,
  computeAuthPath,
  lmsKeygen,
  lmsSign,
  lmsVerify,
  signaturesRemaining,
} from './lms';
import type { LMSPrivateKey, LMSPublicKey } from './lms';
import { lmotsSign, lmotsCoefficients, LMOTS_PARAMS } from './lmots';
import {
  countPositionsReachableAtDepth,
  forgeSignature,
  gatherKnowledge,
  stageReusedSignatures,
} from './forge';
import { parseLeafIndex } from './input';
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
    <div class="shell">
      <main id="main-content">
      <header class="cl-hero">
        <div class="cl-hero-main">
          <h1 class="cl-hero-title">LMS + HSS Vault</h1>
          <p class="cl-hero-sub">Stateful Hash-Based Signatures · RFC 8554</p>
          <p class="cl-hero-desc">Generate an LMS Merkle key, sign firmware, then reuse one LM-OTS index and watch a real forgery succeed against the genuine public key.</p>
        </div>
        <aside class="cl-hero-why" aria-label="Why it matters">
          <span class="cl-hero-why-label">WHY IT MATTERS</span>
          <p class="cl-hero-why-text">Each LM-OTS index is one-time-use: reuse it once and an attacker who sees only the signatures can forge new messages the real key accepts. These schemes guard firmware and boot chains, where a broken index is a compromised device.</p>
        </aside>
      </header>

      <section class="framing" aria-label="How to read this demo">
        <p class="framing-lead">
          A <strong>one-time signature (OTS)</strong> is a key you may safely use <em>exactly once</em>.
          This scheme packs 1024 of them into a Merkle tree so a single public key can sign 1024 times.
          <strong>This demo shows what breaks when you use one twice.</strong>
        </p>
        <p class="framing-order">Read top to bottom: build the tree (1), spend a key (2), see the one-way chain each key is made of (3), then watch a single reused index get weaponized into a live forgery (4).</p>
        <dl class="glossary" aria-label="Notation used in this demo">
          <div><dt>I</dt><dd>this tree's random 16-byte ID (public)</dd></div>
          <div><dt>q</dt><dd>which one-time key (leaf) a signature burns — the leaf index</dd></div>
          <div><dt>T[1]</dt><dd>the Merkle root = the public key everyone verifies against</dd></div>
          <div><dt>LM-OTS</dt><dd>the one-time signature at each leaf (Winternitz hash chains)</dd></div>
          <div><dt>depth</dt><dd>how far down a hash chain a signer reveals for one position</dd></div>
        </dl>
      </section>

      <div class="grid">
        <section class="panel" id="exhibit-1" aria-labelledby="h2-ex1">
          <h2 id="h2-ex1">Exhibit 1: Merkle Tree of OTS Keys</h2>
          <p class="muted">Generate LMS_SHA256_M32_H10 (1024 signatures) and inspect each leaf state. <strong>Run this first</strong> — every later exhibit reuses this exact key.</p>
          <div class="controls">
            <button id="btn-lms-keygen">Generate LMS Keypair</button>
            <span id="lms-progress" class="mono" role="status" aria-live="polite" aria-label="LMS keygen progress">Idle</span>
          </div>
          <div id="lms-pk" class="kv" aria-live="polite"></div>
          <div id="lms-meter" class="meter" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" aria-label="Signatures used"></div>
          <div id="leaf-info" class="note" role="status" aria-live="polite">Click a leaf square to inspect its status.</div>
          <div id="leaf-grid" class="leaf-grid" role="group" aria-label="LMS leaf key grid"></div>
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
            <label for="q-override">Unsafe manual q (leaf index) override (demo corruption)</label>
            <input id="q-override" type="number" min="0" max="1023" value="0" aria-describedby="lms-sign-status" />
            <button id="btn-q-override" class="warn">Set q Unsafely</button>
          </div>
          <div id="lms-sign-status" class="note" role="status" aria-live="polite"></div>
          <div id="lms-signature" class="mono sig" role="status" aria-live="polite" aria-label="LMS signature bytes"></div>
          <div class="danger">
            <h3>Danger Zone</h3>
            <p>Exported state can be cloned or rolled back. Exhibit 5 makes that failure concrete: it burns the live signer&rsquo;s next leaf, then stages stale copies that reuse that same leaf.</p>
            <button id="btn-export-state" class="danger-btn">Export Secret State (Unsafe)</button>
            <textarea id="export-box" readonly placeholder="Unsafe export appears here" aria-label="Exported private state — unsafe"></textarea>
          </div>
        </section>

        <section class="panel span-2" id="exhibit-ots" aria-labelledby="h2-ots">
          <h2 id="h2-ots">Exhibit 3: Inside One OTS &mdash; the Winternitz Chain</h2>
          <p class="muted">
            Every leaf is 34 one-way hash <strong>chains</strong>. To sign, the signer walks each chain
            <em>down to a depth</em> chosen by the message; the revealed value is the signature.
            Because you can only hash <em>forward</em> (never reverse), a verifier can finish the walk
            to the top &mdash; but no attacker can climb back up. <strong>This is the whole basis of the
            forgery below.</strong> Run Exhibit 1 first so the chains use the real key.
          </p>
          <div class="ots-legend mono" aria-hidden="true">
            <span class="ots-swatch known"></span> revealed to attacker
            <span class="ots-swatch reach"></span> attacker can chain forward
            <span class="ots-swatch locked"></span> one-way locked (needs the secret)
          </div>
          <div class="controls stacked">
            <label for="ots-msg-a">Message A (the signer signs this)</label>
            <input id="ots-msg-a" value="firmware v2.3.1" aria-describedby="ots-note" />
            <label for="ots-msg-b">Message B (a different message, same leaf)</label>
            <input id="ots-msg-b" value="install rootkit.bin" aria-describedby="ots-note" />
            <button id="btn-ots-demo">Sign A, then try to reach B</button>
          </div>
          <div id="ots-note" class="note" role="status" aria-live="polite">Generate the LMS key in Exhibit 1, then run this to see real chain depths for these messages.</div>
          <div id="ots-chains" class="ots-chains" role="group" aria-label="Winternitz chains for the first positions"></div>
        </section>

        <section class="panel" id="exhibit-auth" aria-labelledby="h2-ex3">
          <h2 id="h2-ex3">Exhibit 4: Authentication Path Walk</h2>
          <p class="muted">The leaf at <strong>q</strong> plus 10 sibling hashes rebuild the root <strong>T[1]</strong> &mdash; the same tree from Exhibit 1, climbed one level at a time.</p>
          <div id="auth-tree" class="auth-tree" aria-hidden="true"></div>
          <div id="auth-steps" class="tree-climb" aria-live="polite"></div>
        </section>

        <section class="panel span-2" id="exhibit-forgery" aria-labelledby="h2-forge">
          <h2 id="h2-forge">Exhibit 5: Index Reuse &rarr; Live Forgery</h2>
          <p class="muted">
            The headline claim, proven. When a signer reuses one OTS index (the same <strong>q</strong>),
            an attacker who sees <em>only the signatures</em> can forge a brand-new message that the
            genuine public key accepts &mdash; no private key required. This weaponizes exactly the
            one-way chain from Exhibit 3: each reuse can only <em>lower</em> a position's known depth,
            and lower depths reach more messages.
          </p>
          <p id="forge-prereq" class="note amber" role="status">Prerequisite: run Exhibit 1 first to generate the key this attack targets.</p>
          <div class="controls stacked">
            <label for="forge-reuse">Signatures emitted from one burned index after rollback (more copies &rarr; easier forgery)</label>
            <input
              id="forge-reuse"
              type="range"
              min="6"
              max="32"
              value="16"
              aria-describedby="forge-reuse-val"
            />
            <span id="forge-reuse-val" class="mono">16 leaked signatures</span>
            <label for="forge-target">Attacker's forged message (one the signer never approved)</label>
            <input id="forge-target" value="install rootkit.bin &amp;&amp; exfiltrate keys" />
            <button id="btn-forge" class="danger-btn">Mount the attack</button>
            <span id="forge-progress" class="mono" role="status" aria-live="polite">Idle</span>
          </div>
          <ol id="forge-steps" class="steps" aria-live="polite"></ol>
          <div id="forge-reach" class="reach" hidden>
            <p class="reach-label">How much of each hash chain the attacker can reach (averaged over all 34 positions)</p>
            <div class="reach-row">
              <span class="reach-name mono">1 signature</span>
              <div class="reach-bar"><div class="reach-fill single" id="reach-single"></div></div>
              <span class="reach-pct mono" id="reach-single-pct"></span>
            </div>
            <div class="reach-row">
              <span class="reach-name mono">after reuse</span>
              <div class="reach-bar"><div class="reach-fill many" id="reach-many"></div></div>
              <span class="reach-pct mono" id="reach-many-pct"></span>
            </div>
            <p id="reach-plain" class="reach-plain"></p>
            <div id="reach-chains" class="ots-chains compact" role="group" aria-label="Attacker reach per position after reuse"></div>
          </div>
          <div id="forge-verdict" class="verdict" role="status" aria-live="assertive"></div>
          <div id="forge-sig" class="mono sig" role="status" aria-live="polite" aria-label="Forged signature bytes"></div>
        </section>

        <section class="panel" id="exhibit-4" aria-labelledby="h2-ex4">
          <h2 id="h2-ex4">Exhibit 6: HSS Hierarchy</h2>
          <p class="muted">Root H=5 signs leaf-tree public keys; each leaf tree signs up to 1024 messages.</p>
          <div class="controls stacked">
            <button id="btn-hss-keygen">Generate HSS Keypair</button>
            <span id="hss-progress" class="mono" role="status" aria-live="polite" aria-label="HSS keygen progress">Idle</span>
            <label for="hss-message">Message</label>
            <input id="hss-message" value="Signed boot manifest" aria-describedby="hss-sig" />
            <button id="btn-hss-sign">Sign with HSS</button>
          </div>
          <div id="hss-state" class="kv" aria-live="polite"></div>
          <div id="hss-sig" class="mono sig" role="status" aria-live="polite" aria-label="HSS signature result"></div>
        </section>

        <section class="panel" id="exhibit-5" aria-labelledby="h2-ex5">
          <h2 id="h2-ex5">Exhibit 7: When Stateful Signatures Win</h2>
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
      </div>
      </main>
<footer style="margin-top:3rem;padding:2rem 1rem;border-top:1px solid rgba(128,128,128,.25);text-align:center;font-size:.85rem;line-height:1.9;opacity:.85;font-family:ui-monospace,Menlo,Consolas,monospace">
  <div><strong>Related demos:</strong> <a href="https://systemslibrarian.github.io/crypto-lab-lms-ledger/" style="color:#35d6bb">lms-ledger</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/" style="color:#35d6bb">sphincs-ledger</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-merkle-vault/" style="color:#35d6bb">merkle-vault</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-falcon-seal/" style="color:#35d6bb">falcon-seal</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" style="color:#35d6bb">dilithium-seal</a></div>
  <div style="margin-top:.5rem"><a href="https://github.com/systemslibrarian/crypto-lab-lms-xmss" style="color:#35d6bb">Source on GitHub</a> &middot; <a href="https://crypto-lab.systemslibrarian.dev/" style="color:#35d6bb">More crypto-lab demos</a></div>
  <div style="margin-top:.75rem;opacity:.75">&ldquo;So whether you eat or drink or whatever you do, do it all for the glory of God.&rdquo; &mdash; 1 Corinthians 10:31</div>
</footer>
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
    <p><strong>I</strong> <span class="gloss">(tree's random ID)</span> ${shortHex(lmsPublicKey.I, 20)}</p>
    <p><strong>T[1]</strong> <span class="gloss">(Merkle root = public key)</span> ${shortHex(lmsPublicKey.T1, 24)}</p>
    <p><strong>q (leaf index)</strong> <span class="gloss">(next key to burn)</span> ${lmsPrivateKey.q}</p>
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

/* ── Winternitz chain visualization (Exhibit 3 + reach) ──────────────
 * Each LM-OTS position is a hash chain of length 2^w (256 steps, depths 0..255).
 * To sign, the signer walks a position DOWN to the depth the message picks and
 * reveals that value. Because hashing is one-way, whoever holds the depth-d value
 * can advance ("chain forward") to any deeper depth >= d, but can never climb back
 * to a shallower one. We draw each chain as SEGMENTS coarse cells so the shape is
 * legible; the real 0..255 depth is always printed alongside. No math is faked —
 * `depths` come straight from lmotsCoefficients(), the same function signing,
 * verification, and the forgery all use. */
const CHAIN_MAX = 1 << LMOTS_PARAMS.w; // 256 depths per position (0..255)
const CHAIN_SEGMENTS = 20; // coarse cells drawn per chain; depth value shown exactly

function depthToCell(depth: number): number {
  return Math.min(CHAIN_SEGMENTS - 1, Math.round((depth / (CHAIN_MAX - 1)) * (CHAIN_SEGMENTS - 1)));
}

/**
 * Build one chain row. `knownDepth` is where the attacker/signer holds a value.
 * Cells shallower than that are one-way "locked"; the known cell is highlighted;
 * cells deeper are "reach" (chainable forward). If `needDepth` is given, mark the
 * depth a chosen message requires and whether it is reachable (>= knownDepth).
 */
function chainRowHtml(
  posLabel: string,
  knownDepth: number,
  needDepth?: number,
): string {
  const knownCell = depthToCell(knownDepth);
  const needCell = needDepth === undefined ? -1 : depthToCell(needDepth);
  const cells: string[] = [];
  for (let c = 0; c < CHAIN_SEGMENTS; c += 1) {
    let cls = 'chain-cell ';
    if (c < knownCell) cls += 'locked';
    else if (c === knownCell) cls += 'known';
    else cls += 'reach';
    if (c === needCell) cls += ' need';
    cells.push(`<span class="${cls}" aria-hidden="true"></span>`);
  }
  let tail = `<span class="chain-depth mono">d=${knownDepth}</span>`;
  if (needDepth !== undefined) {
    const reachable = needDepth >= knownDepth;
    tail += reachable
      ? `<span class="chain-verdict reachable mono">need d=${needDepth} &check; reachable</span>`
      : `<span class="chain-verdict blocked mono">need d=${needDepth} &cross; SHALLOWER &mdash; locked</span>`;
  }
  return `<div class="chain-row"><span class="chain-pos mono">${posLabel}</span><span class="chain-track">${cells.join('')}</span>${tail}</div>`;
}

const OTS_DEMO_INDEX = 0; // a fresh, unused leaf — this demo only reads chain depths, never signs state

async function handleOtsDemo(): Promise<void> {
  const note = document.querySelector<HTMLDivElement>('#ots-note');
  const chains = document.querySelector<HTMLDivElement>('#ots-chains');
  const inputA = document.querySelector<HTMLInputElement>('#ots-msg-a');
  const inputB = document.querySelector<HTMLInputElement>('#ots-msg-b');
  const btn = document.querySelector<HTMLButtonElement>('#btn-ots-demo');
  if (!note || !chains || !inputA || !inputB) return;

  if (!lmsPrivateKey) {
    note.textContent = 'Generate the LMS keypair in Exhibit 1 first — this reads the real key.';
    note.className = 'note amber';
    return;
  }

  setButtonBusy(btn, true, 'Signing...');
  try {
    const I = lmsPrivateKey.I;
    const q = OTS_DEMO_INDEX;
    // Real LM-OTS: fresh randomizer C per message, real depths from the shared coefficient function.
    const Ca = randomBytes(LMOTS_PARAMS.n);
    const Cb = randomBytes(LMOTS_PARAMS.n);
    const depthsA = await lmotsCoefficients(I, q, Ca, textEncoder.encode(inputA.value));
    const depthsB = await lmotsCoefficients(I, q, Cb, textEncoder.encode(inputB.value));

    const shown = 8; // draw the first 8 of 34 positions; the rest behave identically
    const rows: string[] = [];
    let blocked = 0;
    for (let i = 0; i < LMOTS_PARAMS.p; i += 1) {
      if (depthsB[i] < depthsA[i]) blocked += 1;
    }
    for (let i = 0; i < shown; i += 1) {
      rows.push(chainRowHtml(`pos ${i}`, depthsA[i], depthsB[i]));
    }
    chains.innerHTML =
      `<p class="chain-caption mono">Signing A revealed each position at its own depth (green marker). Message B needs its own depths (blue marker): where B sits DEEPER, the attacker chains forward; where B is SHALLOWER, it is locked.</p>` +
      rows.join('') +
      `<p class="chain-caption mono">Showing positions 0&ndash;${shown - 1} of ${LMOTS_PARAMS.p}.</p>`;
    note.innerHTML = `From <strong>one</strong> signature on A, message B is out of reach at <strong>${blocked} of ${LMOTS_PARAMS.p}</strong> positions (it needs a shallower depth there). A forger must reach <em>all</em> ${LMOTS_PARAMS.p}, so one signature is safe. Exhibit 5 shows how reuse erases that safety.`;
    note.className = 'note';
  } catch (err) {
    note.textContent = err instanceof Error ? err.message : 'Chain demo failed.';
    note.className = 'note critical';
  } finally {
    setButtonBusy(btn, false);
  }
}

/**
 * Draw a real 3-level slice of the Merkle tree around the signed leaf q: the leaf
 * grid from Exhibit 1 and this root-check are the SAME structure, so learners see
 * the connection. Node hashes are read from the genuine treeNodes — the lit path
 * is the actual authentication path, and the slice's top node is a real ancestor
 * of the root T[1]. */
const AUTH_SLICE_LEVELS = 3; // show leaf level + 3 parent levels (8 leaves)

function renderAuthTree(): void {
  const el = document.querySelector<HTMLDivElement>('#auth-tree');
  if (!el) return;
  if (!lmsPrivateKey || lastLmsQ === null) {
    el.innerHTML = '';
    return;
  }
  const h = lmsPrivateKey.h;
  const q = lastLmsQ;
  const nodes = lmsPrivateKey.treeNodes;

  // Path node numbers from the leaf up to the slice top.
  const leafNode = (1 << h) + q;
  const pathNodes: number[] = [];
  let n = leafNode;
  for (let l = 0; l <= AUTH_SLICE_LEVELS; l += 1) {
    pathNodes.push(n);
    n = Math.floor(n / 2);
  }
  const sliceTop = pathNodes[AUTH_SLICE_LEVELS];
  const sliceTopFirstLeaf = sliceTop << AUTH_SLICE_LEVELS; // leftmost leaf under the slice top

  const short = (node: number): string => {
    const val = nodes[node];
    return val ? bytesToHex(val).slice(0, 6) : '······';
  };

  const rows: string[] = [];
  // Top (slice root) down to the leaf level so it reads like a tree.
  for (let level = AUTH_SLICE_LEVELS; level >= 0; level -= 1) {
    const count = 1 << (AUTH_SLICE_LEVELS - level);
    const firstNode = sliceTopFirstLeaf >> level;
    const onPath = pathNodes[level];
    const sibling = onPath ^ 1;
    const cells: string[] = [];
    for (let k = 0; k < count; k += 1) {
      const node = firstNode + k;
      let cls = 'atn';
      let role = '';
      if (node === onPath) {
        cls += level === 0 ? ' atn-leaf' : ' atn-path';
        role = level === 0 ? 'signed leaf q=' + q : 'recomputed';
      } else if (node === sibling) {
        cls += ' atn-sib';
        role = 'sibling from signature';
      }
      const label = role ? ` title="${role}"` : '';
      cells.push(`<span class="${cls}"${label}>${short(node)}</span>`);
    }
    const levelName =
      level === AUTH_SLICE_LEVELS
        ? '&uarr; to T[1]'
        : level === 0
          ? 'leaves'
          : `L${level}`;
    rows.push(`<div class="atn-row"><span class="atn-lname mono">${levelName}</span><div class="atn-cells">${cells.join('')}</div></div>`);
  }
  el.innerHTML =
    `<p class="atn-caption mono">A 3-level slice of the same tree (leaf grid from Exhibit 1). Green = the signed leaf q=${q}. Gold = the sibling the signature supplies at each level. Blue = the node the verifier recomputes, climbing to the real root T[1].</p>` +
    rows.join('') +
    `<p class="atn-caption mono">Above this slice, ${h - AUTH_SLICE_LEVELS} more levels finish the climb to T[1].</p>`;
}

function renderAuthPathDetails(): void {
  const steps = document.querySelector<HTMLDivElement>('#auth-steps');
  if (!steps) {
    return;
  }

  renderAuthTree();

  if (!lastLmsSignature || lastLmsQ === null) {
    steps.innerHTML = '<p class="muted">Sign a message in Exhibit 2 to watch its authentication path rebuild the root.</p>';
    return;
  }

  const auth: string[] = [];
  let offset = 4 + 1124 + 4;
  for (let i = 0; i < LMS_PARAMS.h; i += 1) {
    auth.push(bytesToHex(lastLmsSignature.slice(offset, offset + 32)));
    offset += 32;
  }

  const h = LMS_PARAMS.h;
  let node = (1 << h) + lastLmsQ;
  const rows: string[] = [
    `<div class="climb-start mono">Start: leaf q=${lastLmsQ} &rarr; hash LM-OTS public key candidate into a leaf node.</div>`,
  ];

  for (let level = 0; level < h; level += 1) {
    const isRight = (node & 1) === 1;
    const sib = `${auth[level].slice(0, 16)}&hellip;`;
    const cur = '<span class="climb-node cur" aria-label="computed node">node</span>';
    const sibBox = `<span class="climb-node sib" title="authentication path sibling">sib ${sib}</span>`;
    const pair = isRight ? `${sibBox}${cur}` : `${cur}${sibBox}`;
    rows.push(
      `<div class="climb-row"><span class="climb-level mono">L${level + 1}</span><span class="climb-pair">${pair}</span><span class="climb-arrow" aria-hidden="true">&uarr; hash &rarr; parent</span></div>`,
    );
    node = Math.floor(node / 2);
  }

  rows.push(
    '<div class="climb-root mono">Computed root <span class="climb-node cur">root</span> must equal public key <strong>T[1]</strong> &mdash; otherwise the signature is rejected.</div>',
  );
  steps.innerHTML = rows.join('');
}

/** Gate exhibits that depend on Exhibit 1's key: disable and explain until keygen runs. */
function updatePrerequisiteGates(): void {
  const ready = !!lmsPrivateKey;
  const forgeBtn = document.querySelector<HTMLButtonElement>('#btn-forge');
  const otsBtn = document.querySelector<HTMLButtonElement>('#btn-ots-demo');
  const prereq = document.querySelector<HTMLParagraphElement>('#forge-prereq');
  if (forgeBtn) {
    forgeBtn.disabled = !ready;
    forgeBtn.title = ready ? '' : 'Run Exhibit 1 (Generate LMS Keypair) first';
  }
  if (otsBtn) otsBtn.disabled = !ready;
  if (prereq) {
    prereq.hidden = ready;
  }
}

function updateAllLmsViews(): void {
  renderLmsPublic();
  renderLeafGrid();
  renderAuthPathDetails();
  updatePrerequisiteGates();
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

  if (signaturesRemaining(lmsPrivateKey) === 0) {
    status.textContent = 'ERROR: All 1024 signatures exhausted. Generate a new keypair.';
    status.className = 'note critical';
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
  const q = parseLeafIndex(input.value, lmsPrivateKey.maxQ);
  if (q === null) {
    input.setAttribute('aria-invalid', 'true');
    status.textContent = `ERROR: q must be a whole leaf index from 0 to ${lmsPrivateKey.maxQ - 1}. State was not changed.`;
    status.className = 'note critical';
    return;
  }
  input.removeAttribute('aria-invalid');
  lmsPrivateKey.q = q;
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

/** Mean fraction (0-100) of each OTS chain an attacker can reach given these depths. */
function meanReachPercent(depths: number[]): number {
  const maxDepth = 256;
  const total = depths.reduce((sum, d) => sum + (maxDepth - d) / maxDepth, 0);
  return (total / depths.length) * 100;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function appendForgeStep(text: string, tone: 'normal' | 'alarm' = 'normal'): void {
  const steps = document.querySelector<HTMLOListElement>('#forge-steps');
  if (!steps) return;
  const li = document.createElement('li');
  li.innerHTML = text;
  if (tone === 'alarm') li.className = 'critical';
  steps.appendChild(li);
}

async function handleForge(): Promise<void> {
  const btn = document.querySelector<HTMLButtonElement>('#btn-forge');
  const steps = document.querySelector<HTMLOListElement>('#forge-steps');
  const progress = document.querySelector<HTMLSpanElement>('#forge-progress');
  const verdict = document.querySelector<HTMLDivElement>('#forge-verdict');
  const sigBox = document.querySelector<HTMLDivElement>('#forge-sig');
  const reuseInput = document.querySelector<HTMLInputElement>('#forge-reuse');
  const targetInput = document.querySelector<HTMLInputElement>('#forge-target');
  const reach = document.querySelector<HTMLDivElement>('#forge-reach');
  if (!steps || !verdict || !sigBox || !reuseInput || !targetInput) {
    return;
  }

  steps.innerHTML = '';
  verdict.textContent = '';
  verdict.className = 'verdict';
  sigBox.textContent = '';
  if (reach) reach.hidden = true;

  if (!lmsPrivateKey || !lmsPublicKey) {
    verdict.textContent = 'Generate an LMS keypair in Exhibit 1 first.';
    verdict.className = 'verdict warnish';
    return;
  }

  const reuseCount = Number.parseInt(reuseInput.value, 10);
  const targetMessage = textEncoder.encode(targetInput.value);

  setButtonBusy(btn, true, 'Attacking...');
  if (progress) progress.textContent = 'Staging the leak...';

  try {
    const I = lmsPrivateKey.I;
    if (signaturesRemaining(lmsPrivateKey) === 0) {
      throw new Error('The LMS key is exhausted; generate a new key before staging rollback.');
    }
    const q = lmsPrivateKey.q;
    const authPath = concatBytes(...computeAuthPath(lmsPrivateKey.treeNodes, q, lmsPrivateKey.h));
    const seed = lmsPrivateKey.seed;

    // Burn the actual live next index before modeling stale exported copies.
    // This ties the staged incident to the meter and leaf grid.
    lmsPrivateKey.usedIndexes.add(q);
    lmsPrivateKey.q += 1;
    persistUsedIndexes();
    updateAllLmsViews();

    // Stage 1 — the signer's mistake: many messages signed at one index.
    const messages = Array.from({ length: reuseCount }, (_, i) =>
      textEncoder.encode(`firmware build #${i} (signed honestly)`),
    );
    const leaked = await stageReusedSignatures(
      {
        I,
        q,
        lmsTypecode: lmsPrivateKey.typecode,
        authPath,
        signOts: (m) => lmotsSign(m, { I, q, seed }),
      },
      messages,
    );
    appendForgeStep(
      `The live signer burned <strong>q=${q}</strong>; restored copies then emitted <strong>${reuseCount}</strong> signatures from that same index. Leaf ${q} is now marked used in Exhibit 1.`,
    );

    // Stage 2 — distill what the leak exposes.
    if (progress) progress.textContent = 'Analyzing leaked signatures...';
    const knowledge = await gatherKnowledge(I, leaked);
    const singleDepths = knowledge.perSignatureDepths[0];
    const reachSingle = meanReachPercent(singleDepths);
    const reachMany = meanReachPercent(knowledge.minDepth);
    // Exact threshold statistic over the measured depth vectors. This does not
    // claim how many positions a sampled message actually reaches.
    const MEDIAN = Math.floor((CHAIN_MAX - 1) / 2);
    const hitSingle = countPositionsReachableAtDepth(singleDepths, MEDIAN);
    const hitMany = countPositionsReachableAtDepth(knowledge.minDepth, MEDIAN);
    if (reach) {
      reach.hidden = false;
      const singleFill = document.querySelector<HTMLDivElement>('#reach-single');
      const manyFill = document.querySelector<HTMLDivElement>('#reach-many');
      const singlePct = document.querySelector<HTMLSpanElement>('#reach-single-pct');
      const manyPct = document.querySelector<HTMLSpanElement>('#reach-many-pct');
      if (singleFill) singleFill.style.width = `${reachSingle.toFixed(1)}%`;
      if (manyFill) manyFill.style.width = `${reachMany.toFixed(1)}%`;
      if (singlePct) singlePct.textContent = `${reachSingle.toFixed(1)}%`;
      if (manyPct) manyPct.textContent = `${reachMany.toFixed(1)}%`;
      const plain = document.querySelector<HTMLParagraphElement>('#reach-plain');
      if (plain) {
        plain.innerHTML = `Positions whose known value is at or before midpoint depth ${MEDIAN}: <strong>${hitSingle} &rarr; ${hitMany} of ${LMOTS_PARAMS.p}</strong>. This is a threshold summary of the measured chain depths, not a sampled message. Each reuse only ever <em>lowers</em> a position's known depth (green marker slides left), never raises it &mdash; so the reachable segment can only grow.`;
      }
      // Chain sparkline: draw the first positions' known depth after reuse so the
      // learner sees individual positions, not just an average.
      const reachChains = document.querySelector<HTMLDivElement>('#reach-chains');
      if (reachChains) {
        const shown = 8;
        const rows: string[] = [];
        for (let i = 0; i < shown; i += 1) {
          rows.push(chainRowHtml(`pos ${i}`, knowledge.minDepth[i]));
        }
        reachChains.innerHTML =
          `<p class="chain-caption mono">Known depth per position after ${reuseCount} reuses (green marker = attacker's lowest revealed depth; everything to its right is reachable). Positions 0&ndash;${shown - 1} of ${LMOTS_PARAMS.p}.</p>` +
          rows.join('');
      }
    }
    appendForgeStep(
      `Reuse widened the attacker's reachable range from <strong>${reachSingle.toFixed(1)}%</strong> (one signature) to <strong>${reachMany.toFixed(1)}%</strong> per position. At midpoint depth ${MEDIAN}, the number of positions already reachable rose from <strong>${hitSingle}</strong> to <strong>${hitMany}</strong> of ${LMOTS_PARAMS.p}.`,
    );

    // Stage 3 — grind a randomizer until the chosen message lands within reach.
    if (progress) progress.textContent = 'Forging...';
    const result = await forgeSignature(I, knowledge, targetMessage, lmsPrivateKey.typecode, {
      onProgress: (attempts) => {
        if (progress) progress.textContent = `Forging... ${attempts} attempts`;
      },
    });

    if (!result) {
      verdict.textContent = 'Forgery budget exhausted — increase the reuse count and try again.';
      verdict.className = 'verdict warnish';
      if (progress) progress.textContent = 'No forgery found';
      return;
    }
    appendForgeStep(
      `Forged "<strong>${escapeHtml(targetInput.value)}</strong>" in <strong>${result.attempts}</strong> randomizer attempt(s) &mdash; using only public data.`,
    );

    // Stage 4 — the genuine public key judges the forgery.
    const accepted = await lmsVerify(targetMessage, result.signature, lmsPublicKey);
    if (accepted) {
      verdict.innerHTML =
        '&#10003; FORGED SIGNATURE ACCEPTED by the genuine LMS public key. One reused index destroyed the scheme.';
      verdict.className = 'verdict bad';
      appendForgeStep('The real public key verified an attacker-chosen message. Trust is gone.', 'alarm');
    } else {
      verdict.textContent = 'Unexpected: forged signature did not verify.';
      verdict.className = 'verdict warnish';
    }
    sigBox.textContent = `${result.signature.length} bytes\n${bytesToHex(result.signature).slice(0, 220)}...`;
    if (progress) progress.textContent = 'Done';
  } catch (err) {
    verdict.textContent = err instanceof Error ? err.message : 'Unknown forgery error.';
    verdict.className = 'verdict warnish';
    if (progress) progress.textContent = 'Error - see console';
    console.error(err);
  } finally {
    setButtonBusy(btn, false);
  }
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
  const btnForge = document.querySelector<HTMLButtonElement>('#btn-forge');
  const btnOtsDemo = document.querySelector<HTMLButtonElement>('#btn-ots-demo');
  const forgeReuse = document.querySelector<HTMLInputElement>('#forge-reuse');
  const forgeReuseVal = document.querySelector<HTMLSpanElement>('#forge-reuse-val');
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
  btnForge?.addEventListener('click', () => {
    void handleForge();
  });
  btnOtsDemo?.addEventListener('click', () => {
    void handleOtsDemo();
  });
  forgeReuse?.addEventListener('input', () => {
    if (forgeReuseVal) forgeReuseVal.textContent = `${forgeReuse.value} leaked signatures`;
  });
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
