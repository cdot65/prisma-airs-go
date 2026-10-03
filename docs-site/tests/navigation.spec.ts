import {test, expect} from '@playwright/test';

// Public paths from the former MkDocs navigation are a migration contract.
test('existing guide, example, reference, and release URLs remain readable', async ({request, baseURL}) => {
  const paths = [
    'getting-started/installation/', 'getting-started/configuration/', 'getting-started/quick-start/',
    'services/scan-api/', 'services/runtime-api/', 'services/oauth-lifecycle/',
    'services/model-security-api/', 'services/red-team-api/', 'services/ai-gateway-api/',
    'services/agentguard-api/',
    'examples/runtime-scanning/', 'examples/profile-crud/', 'examples/topic-crud/',
    'examples/red-team-scanning/', 'examples/api-key-rotation/',
    'reference/api-reference/', 'reference/environment-variables/', 'reference/error-handling/',
    'developer/live-verification/', 'developer/feature-quality/', 'developer/releases/',
    'about/release-notes/', 'about/license/',
    'overview/', 'getting-started/', 'getting-started/authentication/', 'examples/',
    'examples/model-security/', 'examples/red-team-inventory/', 'examples/gateway-crud/',
    'examples/agentguard-scanning/',
    'guides/provider-patterns/', 'guides/troubleshooting/', 'developer/development/', 'developer/design-parity/',
    ...['aisec', 'runtime', 'modelsecurity', 'redteam', 'gateway', 'modelsecurity-schema',
      'redteam-schema', 'gateway-schema', 'agentguard', 'agentguard-schema'].map(name => `reference/generated/${name}/`),
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
  await expect(page.locator('#hero-title')).toHaveText('Local control.Gateway intelligence.');
  await expect(page.locator('main > section').first()).toHaveAttribute('aria-labelledby', 'hero-title');
  await expect(page.locator('main > section').nth(1).locator('a')).toHaveCount(4);
  await expect(page.getByRole('link', {name: /Explore AgentGuard preview/})).toHaveAttribute('href', '/prisma-airs-go/examples/agentguard-scanning/');
  await expect(page.locator('.theme-doc-sidebar-container')).toHaveCount(0);
  await page.getByRole('link', {name: 'Get started →', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Getting started', exact: true})).toBeVisible();
  await expect(page.locator('pre').first()).toContainText('go get github.com/cdot65/prisma-airs-go@v0.7.0');
  expect(errors).toEqual([]);
});

test('Go code, Mermaid, and migrated delete callouts render', async ({page}) => {
  await page.goto('developer/architecture/');
  await expect(page.locator('.docusaurus-mermaid-container svg')).toBeVisible();
  await page.goto('examples/topic-crud/');
  await expect(page.locator('.theme-admonition').filter({hasText: 'ForceDelete response'})).toBeVisible();
  await expect(page.locator('pre.language-go').first()).toContainText('runtime.NewClient');
});

test('desktop articles use the harness reading column without a right-hand contents panel', async ({page}) => {
  await page.setViewportSize({width: 1440, height: 1000});
  await page.goto('getting-started/');
  await expect(page.locator('article h1')).toHaveText('Getting started');
  await expect(page.locator('aside[aria-label="On-page navigation"]')).toHaveCount(0);
  await expect(page.locator('.theme-doc-toc-desktop')).toHaveCount(0);
  await expect(page.locator('.theme-doc-toc-mobile')).toBeHidden();
  expect(await page.locator('article').evaluate(element => element.getBoundingClientRect().width)).toBeGreaterThan(800);
});

test('mobile homepage and API reference fit the viewport and expose navigation', async ({page}) => {
  await page.setViewportSize({width: 390, height: 844});
  await page.goto('./');
  await page.getByRole('button', {name: 'Toggle navigation bar'}).click();
  await expect(page.locator('.navbar-sidebar')).toBeVisible();
  await page.goto('getting-started/');
  await expect(page.locator('.theme-doc-toc-mobile')).toBeVisible();
  await page.goto('reference/api-reference/');
  await expect(page.getByRole('heading', {name: 'API Reference', exact: true})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(391);
});


test('reference includes all service clients and schema catalogs', async ({page}) => {
  await page.goto('reference/generated/gateway/');
  await expect(page.getByRole('heading', {name: 'ConfigsClient.ListVersions'})).toBeVisible();
  await expect(page.getByRole('heading', {name: 'APIKeysClient.ListForKind'})).toBeVisible();
  await page.goto('reference/generated/redteam/');
  await expect(page.getByRole('heading', {name: 'NetworkBrokerClient', level: 2})).toBeVisible();
  await page.goto('reference/generated/modelsecurity/');
  await expect(page.locator('#modelsclientlist')).toBeVisible();
  await page.goto('reference/generated/agentguard/');
  await expect(page.getByRole('heading', {name: 'ScansClient.UploadComplete'})).toBeVisible();
  await expect(page.getByRole('heading', {name: 'RuleInstancesClient.Update'})).toBeVisible();
  await page.goto('examples/agentguard-scanning/');
  await expect(page.locator('pre.language-go').first()).toContainText('agentguard.NewClient');
});

for (const viewport of [{width: 1440, height: 1000}, {width: 1024, height: 768}, {width: 390, height: 844}]) {
  test(`all homepage paths work at ${viewport.width}px`, async ({page}) => {
    await page.setViewportSize(viewport);
    await page.goto('./');
    const links = await page.locator('main a').evaluateAll(elements => elements.map(element => (element as HTMLAnchorElement).href));
    for (const href of links) {
      const response = await page.goto(href);
      expect(response?.status()).toBe(200);
      await expect(page.locator('article h1')).toBeVisible();
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width);
  });
}
