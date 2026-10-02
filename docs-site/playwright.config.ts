import {defineConfig} from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  use: {
    baseURL: process.env.DOCS_URL || 'http://127.0.0.1:4173/prisma-airs-go/',
    launchOptions: {executablePath: process.env.CHROMIUM_PATH || undefined},
  },
  webServer: process.env.DOCS_URL ? undefined : {
    command: 'npm run serve -- --host 127.0.0.1 --port 4173',
    url: 'http://127.0.0.1:4173/prisma-airs-go/',
    reuseExistingServer: !process.env.CI,
  },
});
