import fs from 'node:fs';
import path from 'node:path';
import { defineConfig } from '@playwright/test';

const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
    process.loadEnvFile(envFile);
}

/**
 * Screenshots of the pages for the docs: npm run screenshots. Kept apart from the browser tests,
 * which record nothing because pages show codes. Here codes are replaced with placeholders before
 * anything is captured, and nothing else is recorded.
 */
export default defineConfig({
    testDir: './screenshots',
    workers: 1,
    fullyParallel: false,
    retries: 0,
    timeout: 180_000,
    expect: { timeout: 15_000 },
    reporter: [['list']],
    use: {
        channel: process.env.E2E_BROWSER_CHANNEL ?? 'chrome',
        headless: true,
        viewport: { width: 1100, height: 760 },
        deviceScaleFactor: 2,
        trace: 'off',
        screenshot: 'off',
        video: 'off',
    },
});
