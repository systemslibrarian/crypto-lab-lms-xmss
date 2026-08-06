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
  await page.emulateMedia({ reducedMotion: 'reduce' });
}

async function checkGradientContrast(page: Page): Promise<void> {
  const badElements = await page.evaluate(() => {
    function getLuminance(r: number, g: number, b: number) {
      const a = [r, g, b].map(v => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      });
      return a[0] * 0.2126 + a[1] * 0.7152 + a[2] * 0.0722;
    }
    function parseColor(str: string) {
      if (str.startsWith('color(srgb')) {
        const m = str.match(/color\(srgb ([\d.]+) ([\d.]+) ([\d.]+)/);
        if (m) return [parseFloat(m[1])*255, parseFloat(m[2])*255, parseFloat(m[3])*255];
      }
      const m = str.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
      return m ? [parseInt(m[1]), parseInt(m[2]), parseInt(m[3])] : [0, 0, 0];
    }
    function getContrast(rgb1: number[], rgb2: number[]) {
      const l1 = getLuminance(rgb1[0], rgb1[1], rgb1[2]);
      const l2 = getLuminance(rgb2[0], rgb2[1], rgb2[2]);
      return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    }
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
    let node: Node | null;
    const fails = [];
    while ((node = walker.nextNode())) {
      if (!node.nodeValue || !node.nodeValue.trim()) continue;
      const el = node.parentElement;
      if (!el || el.closest('svg') || el.getBoundingClientRect().width === 0) continue;
      const style = getComputedStyle(el);
      const color = parseColor(style.color);
      let bgEl: HTMLElement | null = el;
      let bgs: number[][] = [];
      let foundSolid = false;
      while (bgEl) {
        const bgStyle = getComputedStyle(bgEl);
        if (bgStyle.backgroundImage.includes('gradient')) {
          bgs = [...bgStyle.backgroundImage.matchAll(/rgba?\(\d+,\s*\d+,\s*\d+(?:,\s*[\d.]+)?\)/g)]
            .filter(m => m[0] !== 'rgba(0, 0, 0, 0)')
            .map(m => parseColor(m[0]));
          if (bgs.length > 0) break;
        } else if (bgStyle.backgroundColor !== 'rgba(0, 0, 0, 0)' && bgStyle.backgroundColor !== 'transparent') {
          foundSolid = true;
          break;
        }
        bgEl = bgEl.parentElement;
      }
      if (bgs.length > 0 && !foundSolid) {
        let minRatio = Infinity;
        for (const bg of bgs) {
          const ratio = getContrast(color, bg);
          if (ratio < minRatio) minRatio = ratio;
        }
        if (minRatio < 4.5) {
          fails.push({ text: node.nodeValue.trim().substring(0, 30), ratio: minRatio });
        }
      }
    }
    return fails;
  });
  expect(badElements).toEqual([]);
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
  await expect(page.locator('h1')).toBeVisible();
  await revealAll(page);
  await scan(page);
  await checkGradientContrast(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('h1')).toBeVisible();
  await revealAll(page);
  await scan(page);
  await checkGradientContrast(page);
});
