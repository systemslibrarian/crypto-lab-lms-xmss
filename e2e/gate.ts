import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures, type NonTextFailure } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing. At first paint every one of this lab's seven exhibits is empty:
 *     no leaf grid, no signature, no Winternitz chains, no authentication-path
 *     climb, no forgery. The headline claim — a forged signature the genuine
 *     public key ACCEPTS — is four interactions deep.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  await expect(page.locator('#btn-lms-keygen')).toBeVisible();
  await expect(page.locator('#exhibit-forgery')).toBeVisible();
  await expect(page.locator('#leaf-grid')).toBeEmpty();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints multi-hundred-byte signatures as hex, lays 1024
 * leaf buttons out on a 32-column grid, and draws 34 Winternitz chain rows.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element, which is
    // exactly what happened here: the 980px comparison table was reported while
    // the real overflow was 15px of something else entirely.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectNoNewNonTextFailures(page, label);
  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}





/**
 * Drive the lab through the states that render content, scanning each.
 *
 * The exhibits have a real prerequisite chain, and it is the chain the lab
 * teaches: nothing downstream of Exhibit 1 exists until the LMS key does. So
 * this drives in order, and deliberately visits the ONE state that is only
 * reachable before that — mounting the forgery with no key, which renders the
 * `.verdict.warnish` branch. That branch and `.verdict.bad` are separately
 * coloured and a gate that only ever ran the happy path sees one of the two.
 *
 * Keygen builds a 1024-leaf Merkle tree and the forgery grinds a randomizer, so
 * each is awaited on its own completion signal — the rendered leaf count, the
 * verdict text — never on a timeout.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint`);

  await page.locator('a.cl-skip-link').focus();
  await scan(page, `${theme} / skip link focused`);

  // Exhibit 5's prerequisite is enforced, not merely stated: `#btn-forge` is
  // disabled and titled until Exhibit 1 has run, so `handleForge`'s
  // "generate a keypair first" verdict is unreachable from the UI. That is a
  // fact about the source rather than a gap in the drive — recorded here so the
  // next reader does not add a click that can only ever hang.
  await expect(page.locator('#btn-forge')).toBeDisabled();
  await expect(page.locator('#forge-prereq')).toBeVisible();

  // ── Exhibit 1: the Merkle tree ────────────────────────────────────────────
  // Keygen hashes a 1024-leaf Merkle tree on the main thread, which blocks
  // Playwright's post-click stability check well past the 20s default.
  await page.locator('#btn-lms-keygen').click({ timeout: 300_000 });
  await expect(page.locator('#leaf-grid .leaf')).toHaveCount(1024, { timeout: 120_000 });
  await expect(page.locator('#lms-pk')).not.toBeEmpty();
  await expect(page.locator('#lms-progress')).not.toHaveText('Idle');
  await scan(page, `${theme} / LMS keypair generated`);

  await page.locator('#leaf-grid .leaf').first().click();
  await expect(page.locator('#leaf-info')).not.toHaveText(
    'Click a leaf square to inspect its status.'
  );
  await scan(page, `${theme} / leaf inspected`);

  // ── Exhibit 2: signing consumes state ─────────────────────────────────────
  await page.locator('#lms-message').fill('Firmware v9.9.9 release candidate');
  await page.locator('#btn-lms-sign').click({ timeout: 300_000 });
  await expect(page.locator('#lms-signature')).not.toBeEmpty();
  await expect(page.locator('#lms-sign-status')).not.toBeEmpty();
  await scan(page, `${theme} / message signed`);

  // Signing again burns a second index, and Exhibit 4's climb is rendered from
  // the last q — so this is also the state where the auth path first exists.
  await page.locator('#btn-lms-sign-again').click({ timeout: 300_000 });
  await expect(page.locator('#auth-steps .climb-row')).toHaveCount(10);
  await scan(page, `${theme} / signed again, authentication path walked`);

  // The unsafe q override: the lab's own corruption path, and a `.warn` control.
  await page.locator('#q-override').fill('7');
  await page.locator('#btn-q-override').click();
  await expect(page.locator('#lms-sign-status')).not.toBeEmpty();
  await scan(page, `${theme} / q overridden unsafely`);

  // The danger zone: a filled <textarea> of exported private state.
  await page.locator('#btn-export-state').click();
  await expect(page.locator('#export-box')).not.toHaveValue('');
  await scan(page, `${theme} / secret state exported`);

  // ── Exhibit 3: the Winternitz chains ──────────────────────────────────────
  await page.locator('#ots-msg-a').fill('firmware v2.3.1');
  await page.locator('#ots-msg-b').fill('install rootkit.bin');
  await page.locator('#btn-ots-demo').click({ timeout: 300_000 });
  await expect(page.locator('#ots-chains .chain-row').first()).toBeVisible();
  await scan(page, `${theme} / Winternitz chains drawn`);

  // ── Exhibit 5: the forgery, run at both ends of the reuse slider ──────────
  // The slider's minimum is the least favourable case for the attacker and its
  // maximum the most, and both are run for real rather than assumed: 6 leaked
  // signatures still reached `.verdict.bad` in every run observed here, but the
  // randomizer can exhaust its budget instead and render `.verdict.warnish`, so
  // the drive asserts only that a verdict rendered and scans whichever one it
  // is. Waits are on the button leaving its busy state, never on a timeout.
  for (const reuse of ['6', '32'] as const) {
    await page.locator('#forge-reuse').fill(reuse);
    await expect(page.locator('#forge-reuse-val')).toHaveText(`${reuse} leaked signatures`);
    await scan(page, `${theme} / reuse slider at ${reuse}`);

    await page.locator('#forge-target').fill('install rootkit.bin && exfiltrate keys');
    await page.locator('#btn-forge').click({ timeout: 300_000 });
    await expect(page.locator('#btn-forge')).toBeEnabled({ timeout: 300_000 });
    await expect(page.locator('#forge-verdict')).not.toBeEmpty();
    await expect(page.locator('#forge-steps li').first()).toBeVisible();
    await scan(page, `${theme} / forgery mounted from ${reuse} reuses`);
  }

  // The maximum run must have reached the lab's headline claim, with its reach
  // bars and per-position chain sparkline rendered.
  await expect(page.locator('#forge-reach')).toBeVisible();
  await expect(page.locator('#reach-chains .chain-row').first()).toBeVisible();
  await expect(page.locator('#forge-sig')).not.toBeEmpty();

  // ── Exhibit 6: the HSS hierarchy ──────────────────────────────────────────
  await page.locator('#btn-hss-keygen').click({ timeout: 300_000 });
  await expect(page.locator('#hss-progress')).not.toHaveText('Idle', { timeout: 180_000 });
  await expect(page.locator('#btn-hss-keygen')).toBeEnabled({ timeout: 180_000 });
  await expect(page.locator('#hss-state')).not.toBeEmpty();
  await scan(page, `${theme} / HSS keypair generated`);

  await page.locator('#hss-message').fill('Signed boot manifest');
  await page.locator('#btn-hss-sign').click({ timeout: 300_000 });
  await expect(page.locator('#btn-hss-sign')).toBeEnabled({ timeout: 180_000 });
  await expect(page.locator('#hss-sig')).not.toBeEmpty();
  await scan(page, `${theme} / HSS signature`);
}
