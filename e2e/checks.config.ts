import fs from 'node:fs';
import path from 'node:path';
import { defineConfig } from '@playwright/test';

const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
    process.loadEnvFile(envFile);
}

/**
 * Checks that need a particular Admin Console setup on the test Identity Server, so npm test never
 * runs them: E2E_CHECK=<name> npm run checks. checks/global-setup.ts makes that setup with amcli
 * from checks/setup/<name>.json, and puts the console back afterwards. Nothing is recorded.
 */
export default defineConfig({
    testDir: './checks',
    globalSetup: './checks/global-setup.ts',
    workers: 1,
    fullyParallel: false,
    retries: 0,
    timeout: 180_000,
    expect: { timeout: 15_000 },
    reporter: [['list']],
    use: {
        channel: process.env.E2E_BROWSER_CHANNEL ?? 'chrome',
        headless: true,
        trace: 'off',
        screenshot: 'off',
        video: 'off',
    },
});
