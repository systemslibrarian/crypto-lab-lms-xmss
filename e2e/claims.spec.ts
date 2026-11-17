import { expect, test } from '@playwright/test';

test('invalid q overrides preserve state and rollback burns a visible live leaf', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('.');
  await page.getByRole('button', { name: 'Generate LMS Keypair' }).click();
  await expect(page.locator('#lms-progress')).toHaveText('Ready', { timeout: 60_000 });

  const qLine = page.locator('#lms-pk p').filter({ hasText: 'q (leaf index)' });
  await expect(qLine).toContainText('0');
  await page.locator('#q-override').fill('-5');
  await page.getByRole('button', { name: 'Set q Unsafely' }).click();
  await expect(page.locator('#lms-sign-status')).toContainText('State was not changed');
  await expect(page.locator('#q-override')).toHaveAttribute('aria-invalid', 'true');
  await expect(qLine).toContainText('0');

  await page.getByRole('button', { name: 'Mount the attack' }).click();
  await expect(page.locator('#forge-steps li').first()).toContainText(
    'The live signer burned q=0',
    { timeout: 60_000 },
  );
  // The name now opens with the digit the leaf shows, so that the accessible
  // name contains the visible text (axe label-content-name-mismatch).
  await expect(page.locator('.leaf[data-leaf="0"]')).toHaveAttribute('aria-label', '0: leaf 0, used');
  await expect(qLine).toContainText('1');
  await expect(page.locator('#reach-plain')).toContainText(
    'Positions whose known value is at or before midpoint depth 127',
    { timeout: 60_000 },
  );
  await expect(page.locator('#reach-plain')).toContainText('not a sampled message');
});

test('the CNSA 2.0 line names ML-DSA, as the FAQ table does', async ({ page }) => {
  /* The deployment bullet and README line 59 presented the SP 800-208 schemes
   * as the CNSA 2.0 software- and firmware-signing algorithms, full stop. NSA's
   * CNSA 2.0 and Quantum Computing FAQ (U/OO/6072712-26 | PP-26-3194 | October
   * 2026 Ver. 2.2) puts ML-DSA under "General Purpose Algorithms" for "digital
   * signatures in any use case, including signing firmware and software", and
   * LMS/XMSS under "Algorithms Allowed in Specific Applications"; asked "Can I
   * use ML-DSA for firmware or software signing?" it answers "Yes", adding
   * "Validated ML-DSA is approved for all signing use cases" and that NSA wants
   * the transition to "begin now (using LMS and XMSS) whenever possible" because
   * those "have been commercially available longer".
   *
   * The sibling labs lms-ledger and harvest-timeline already say this. */
  await page.goto('.');
  const bullet = page.locator('li', { hasText: 'Real deployments' }).first();
  const text = (await bullet.innerText()).replace(/\s+/g, ' ');

  expect(text).toContain('ML-DSA');
  expect(text).toContain('Validated ML-DSA is approved for all signing use cases');
  expect(text).toContain('Algorithms Allowed in Specific Applications');
  expect(text).toContain('Ver. 2.2, October 2026');
  expect(text).toContain('been commercially available longer');
  // The old formulation treated SP 800-208 as the whole answer.
  expect(text).not.toContain('CNSA 2.0 software- and firmware-signing algorithms (SP 800-208)');
});
