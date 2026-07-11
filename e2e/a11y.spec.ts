import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate. Deploys are already gated on the internal
 * phase gates; this gates them on accessibility the same way. Scans the full
 * page with every collapsible expanded and animations neutralized, in both
 * the default (dark) theme and the light theme.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** Expand every collapsible / class-toggled panel so hidden content is scanned. */
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Native <details>
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
    // Class-toggled panels/accordions/tabs/modals.
    for (const el of Array.from(
      document.querySelectorAll<HTMLElement>('.reach, [hidden]'),
    )) {
      el.removeAttribute('hidden');
      el.classList.add('open', 'active');
      el.style.display = '';
    }
  });
  // Neutralize animations/transitions/opacity so nothing is mid-fade during scan.
  await page.addStyleTag({
    content: `*, *::before, *::after {
      transition: none !important;
      animation: none !important;
    }`,
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealAll(page);
  await scan(page);
});
