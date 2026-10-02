import {test, expect} from '@playwright/test';

// Public paths from the former MkDocs navigation are a migration contract.
test('existing guide, example, reference, and release URLs remain readable', async ({request, baseURL}) => {
  const paths = [
    'getting-started/installation/', 'getting-started/configuration/', 'getting-started/quick-start/',
    'services/scan-api/', 'services/runtime-api/', 'services/oauth-lifecycle/',
    'services/model-security-api/', 'services/red-team-api/', 'services/ai-gateway-api/',
    'examples/runtime-scanning/', 'examples/profile-crud/', 'examples/topic-crud/',
    'examples/red-team-scanning/', 'examples/api-key-rotation/',
    'reference/api-reference/', 'reference/environment-variables/', 'reference/error-handling/',
    'developer/live-verification/', 'developer/feature-quality/', 'developer/releases/',
    'about/release-notes/', 'about/license/',
  ];
  for (const path of paths) {
    const response = await request.get(new URL(path, baseURL).href);
    expect(response.status(), path).toBe(200);
    const html = await response.text();
    expect(html, path).toContain('<h1');
    const canonical = html.match(/<link\b[^>]*rel=["']?canonical["']?[^>]*href=["']?([^"' >]+)/)?.[1];
    expect(canonical, path).toBe(`https://cdot65.github.io/prisma-airs-go/${path}`);
  }
});

test('homepage links reach Go-specific guides without browser errors', async ({page}) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('./');
  await expect(page.getByRole('heading', {name: 'Prisma AIRS Go SDK', exact: true})).toBeVisible();
  await expect(page.locator('.sdk-domain')).toHaveCount(4);
  await page.getByRole('link', {name: 'Get started', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Installation', exact: true})).toBeVisible();
  await expect(page.locator('pre').first()).toContainText('go get github.com/cdot65/prisma-airs-go@v0.6.0');
  expect(errors).toEqual([]);
});

test('Go code, Mermaid, and migrated delete callouts render', async ({page}) => {
  await page.goto('developer/architecture/');
  await expect(page.locator('.docusaurus-mermaid-container svg')).toBeVisible();
  await page.goto('examples/topic-crud/');
  await expect(page.locator('.theme-admonition').filter({hasText: 'ForceDelete response'})).toBeVisible();
  await expect(page.locator('pre.language-go').first()).toContainText('runtime.NewClient');
});

test('desktop on-page navigation can collapse and expand accessibly', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 1000});
  await page.goto('services/ai-gateway-api/');
  const toggle = page.getByRole('button', {name: 'Collapse on-page navigation'});
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  await toggle.click();
  await expect(page.locator('#doc-page-navigation')).toBeHidden();
  await page.getByRole('button', {name: 'Expand on-page navigation'}).click();
  await expect(page.locator('#doc-page-navigation')).toBeVisible();
});

test('mobile homepage and API reference fit the viewport and expose navigation', async ({page}) => {
  await page.setViewportSize({width: 390, height: 844});
  await page.goto('./');
  await page.getByRole('button', {name: 'Toggle navigation bar'}).click();
  await expect(page.locator('.navbar-sidebar')).toBeVisible();
  await page.goto('reference/api-reference/');
  await expect(page.getByRole('heading', {name: 'API Reference', exact: true})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(391);
});
