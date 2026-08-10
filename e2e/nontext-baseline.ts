/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  "control-boundary|a.cl-btn": { ratio: 2.45, required: 3.0, unverified: false },
  "control-boundary|button#btn-hss-keygen": { ratio: 2.14, required: 3.0, unverified: false },
  "control-boundary|button#btn-hss-sign": { ratio: 2.06, required: 3.0, unverified: false },
  "control-boundary|button#btn-lms-keygen": { ratio: 2.1, required: 3.0, unverified: false },
  "control-boundary|button#btn-lms-sign": { ratio: 2.16, required: 3.0, unverified: false },
  "control-boundary|button#btn-lms-sign-again": { ratio: 2.15, required: 3.0, unverified: false },
  "control-boundary|button#btn-ots-demo": { ratio: 2.05, required: 3.0, unverified: false },
  "control-boundary|button#cl-theme-toggle.cl-btn.cl-icon": { ratio: 2.45, required: 3.0, unverified: false },
  "control-boundary|button.leaf.fresh": { ratio: 1.74, required: 3.0, unverified: false },
  "control-boundary|button.leaf.used": { ratio: 1.52, required: 3.0, unverified: false }
};
