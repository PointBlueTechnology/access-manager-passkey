import fs from 'node:fs';
import path from 'node:path';
import { defineConfig } from '@playwright/test';

const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
    process.loadEnvFile(envFile);
}

export default defineConfig({
    testDir: './tests',
    // The tests share accounts and build on each other, so they run one at a time, in order
    workers: 1,
    fullyParallel: false,
    retries: 0,
    timeout: 180_000,
    expect: { timeout: 15_000 },
    reporter: [['list']],
    use: {
        channel: process.env.E2E_BROWSER_CHANNEL ?? 'chrome',
        headless: true,
        // Pages show recovery codes and helpdesk tokens, and the password fields are filled in, so
        // nothing is recorded that could keep them
        trace: 'off',
        screenshot: 'off',
        video: 'off',
    },
});
