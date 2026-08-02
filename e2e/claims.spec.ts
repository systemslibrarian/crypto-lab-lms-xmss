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
  await expect(page.locator('.leaf[data-leaf="0"]')).toHaveAttribute('aria-label', 'Leaf 0: used');
  await expect(qLine).toContainText('1');
  await expect(page.locator('#reach-plain')).toContainText(
    'Positions whose known value is at or before midpoint depth 127',
    { timeout: 60_000 },
  );
  await expect(page.locator('#reach-plain')).toContainText('not a sampled message');
});
