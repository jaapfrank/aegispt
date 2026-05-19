import { defineConfig, devices } from '@playwright/test';

const port = Number(process.env.UI_V2_PLAYWRIGHT_PORT ?? 5174);

export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  expect: {
    timeout: 7_500,
  },
  fullyParallel: true,
  reporter: [['list']],
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: 'on-first-retry',
  },
  webServer: {
    command: `npm run dev -- --host 127.0.0.1 --port ${port}`,
    url: `http://127.0.0.1:${port}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
