import path from 'node:path';
import { type Page, expect, test } from '@playwright/test';
import { type Account, env } from '../lib/env';
import { Session } from '../lib/nam';

/**
 * Captures each page for the docs into docs/images. Pages that ask for a passkey as soon as they
 * load are held at that moment: the browser's passkey request is made to wait, as if the user's
 * device were showing its prompt. Recovery codes are swapped for made-up ones before capture, and
 * each contract's card, whose title every site sets for itself, is given a plain descriptive one.
 */
test.describe.configure({ mode: 'serial' });

const OUT = path.join(__dirname, '../../docs/images');

/** Card titles for the screenshots; the test server's are its contract IDs. */
const CARD_TITLES: Record<string, string> = {
    [env.contracts.login]: 'Sign in with a passkey',
    [env.contracts.manage]: 'Manage your passkeys',
    [env.contracts.recovery]: 'Recover your account',
    [env.contracts.helpdesk]: 'Passkey helpdesk',
};

/** Made-up codes in the real format (base32, groups of four), never real ones. */
const SAMPLE_CODES = [
    'K7QM-4TXB-R2WN-H5PD', 'B3VJ-Q6ZL-M2XC-T7RA', 'W5HN-2KDF-Y7QS-L3ME', 'P4RT-Z6GB-J2VX-N7WQ',
    'D2MC-X5LK-R7TB-F3HY', 'S6QW-3NJP-V4ZD-K2GM', 'H7LB-T2YR-C5XQ-W3NF', 'Z3KD-P6MV-G2HT-R5LS',
    'N5XF-7BQC-T3WJ-Y2PK', 'R2GT-K4WM-X6LB-D7QZ',
];

let user: Account;
let agent: Account;

test.beforeAll(() => {
    user = env.user();
    agent = env.agent();
});

async function shot(page: Page, name: string): Promise<void> {
    // Let fonts and the stock page's own scripts settle
    await page.waitForTimeout(800);
    const bottom = await page.evaluate((titles: Record<string, string>) => {
        // The card's title is plain text NAM prints from the contract's settings
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        for (let node = walker.nextNode(); node; node = walker.nextNode()) {
            const text = node.textContent?.trim() ?? '';
            if (titles[text]) {
                node.textContent = node.textContent!.replace(text, titles[text]);
            }
        }
        const form = document.querySelector('#pk_form') ?? document.body;
        return Math.ceil(form.getBoundingClientRect().bottom + window.scrollY);
    }, CARD_TITLES);
    const width = page.viewportSize()!.width;
    await page.screenshot({ path: path.join(OUT, `${name}.png`), clip: { x: 0, y: 0, width, height: bottom + 40 } });
}

/**
 * The browser's passkey request never finishes, as while the user's device shows its prompt. Set on
 * this page now and on any it loads, since NAM brings most pages in without a full page load.
 */
async function holdPasskeyRequests(page: Page): Promise<void> {
    const hold = () => {
        if (navigator.credentials) {
            navigator.credentials.get = () => new Promise(() => undefined);
        }
    };
    await page.addInitScript(hold);
    await page.evaluate(hold);
}

test('passkey-only sign-in', async ({ browser }) => {
    const session = await Session.open(browser, user, env.contracts.login);
    try {
        expect(await session.driveTo(['login'])).toBe('login');
        await shot(session.page, 'passkey-sign-in');
    } finally {
        await session.close();
    }
});

test('signing in with a user ID', async ({ browser }) => {
    const session = await Session.open(browser, user, env.contracts.login);
    try {
        expect(await session.driveTo(['login'])).toBe('login');
        await holdPasskeyRequests(session.page);
        await session.page.fill('#pk_userid', user.id);
        await session.page.click('#pk_continue');
        await session.page.waitForSelector('#pk_reset');
        await shot(session.page, 'passkey-sign-in-with-id');
    } finally {
        await session.close();
    }
});

test('confirming with a passkey', async ({ browser }) => {
    const session = await Session.open(browser, user, env.contracts.manage);
    try {
        await holdPasskeyRequests(session.page);
        expect(await session.driveTo(['mfa'])).toBe('mfa');
        await shot(session.page, 'passkey-confirm');
    } finally {
        await session.close();
    }
});

test('managing passkeys, adding one, and recovery codes', async ({ browser }) => {
    const session = await Session.open(browser, user, env.contracts.manage);
    try {
        expect(await session.driveTo(['manage'])).toBe('manage');
        await shot(session.page, 'manage');

        expect(await session.click('#pk_add')).toBe('register');
        await shot(session.page, 'create-passkey');
        await session.page.goBack().catch(() => undefined);
    } finally {
        await session.close();
    }

    const codes = await Session.open(browser, user, env.contracts.manage);
    try {
        expect(await codes.driveTo(['manage'])).toBe('manage');
        expect(await codes.click('#pk_codes')).toBe('codes');
        // Placeholders, so no real code is ever captured
        await codes.page.evaluate((samples: string[]) => {
            document.querySelectorAll('#pk_code_list div').forEach((element, i) => {
                element.textContent = samples[i % samples.length];
            });
        }, SAMPLE_CODES);
        await shot(codes.page, 'recovery-codes');
        expect(await codes.click('#pk_done')).toBe('manage');
    } finally {
        await codes.close();
    }
});

test('recovery', async ({ browser }) => {
    const session = await Session.open(browser, user, env.contracts.recovery);
    try {
        expect(await session.driveTo(['recovery'])).toBe('recovery');
        await shot(session.page, 'recovery');
    } finally {
        await session.close();
    }
});

test('helpdesk', async ({ browser }) => {
    const session = await Session.open(browser, agent, env.contracts.helpdesk);
    try {
        expect(await session.driveTo(['helpdesk'])).toBe('helpdesk');
        await shot(session.page, 'helpdesk');
    } finally {
        await session.close();
    }
});
