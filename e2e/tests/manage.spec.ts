import { expect, test } from '@playwright/test';
import { type Account, env } from '../lib/env';
import { msg } from '../lib/messages';
import { type Kind, Session } from '../lib/nam';

/**
 * Rules around changing passkeys: the browser is told which passkeys the account already has, and a
 * passkey sign-in in one contract doesn't stand in for the passkey another contract asks for later.
 */
test.describe.configure({ mode: 'serial' });

let user: Account;
let agent: Account;

test.beforeAll(() => {
    user = env.user();
    agent = env.agent();
});

test('the accounts have a software passkey', async ({ browser }) => {
    await Session.enroll(browser, user, env.contracts.manage);
    await Session.enroll(browser, agent, env.contracts.manage);
    // Leftovers from an earlier run that stopped partway
    const session = await Session.open(browser, user, env.contracts.manage);
    try {
        expect(await session.driveTo(['manage'])).toBe('manage');
        await session.removePasskeysNamed('e2e-duplicate');
    } finally {
        await session.close();
    }
});

test('a browser that already holds one of the account\'s passkeys is refused another', async ({ browser }) => {
    const session = await Session.open(browser, user, env.contracts.manage);
    try {
        expect(await session.driveTo(['manage'])).toBe('manage');
        const before = await session.authenticator.credentials();
        expect(await session.click('#pk_add')).toBe('register');
        await session.page.fill('#pk_name', 'e2e-duplicate');
        await session.page.click('#pk_button');
        await expect(session.page.locator('#pk_msg')).toHaveText(msg('error.alreadyRegistered'));
        // Nothing was replaced in the browser: it still holds exactly the passkey it had
        expect((await session.authenticator.credentials()).map(c => c.credentialId))
            .toEqual(before.map(c => c.credentialId));
        expect(await session.click('#pk_cancel')).toBe('manage');
        await expect(session.page.locator('.pk-remove[data-name="e2e-duplicate"]')).toHaveCount(0);
    } finally {
        await session.close();
    }
});

for (const [who, contract, page] of [['user', 'manage', 'manage'], ['agent', 'helpdesk', 'helpdesk']] as const) {
    test(`a passkey sign-in doesn't open the ${contract} contract started afterwards`, async ({ browser }) => {
        const account = who === 'user' ? user : agent;
        const session = await Session.open(browser, account, env.contracts.login);
        try {
            expect(await session.driveTo(['login'])).toBe('login');
            expect(await session.click('#pk_button')).toBe('finished');

            const signedIn = (await session.authenticator.credentials())[0].signCount;

            // Same browser session: a password is asked for, and then the passkey again, which the
            // page asks for by itself, so its use shows in the passkey's signature counter
            await session.page.goto(`/nidp/jsp/main.jsp?id=${encodeURIComponent(env.contracts[contract])}&sid=0`);
            expect(await session.driveTo([page as Kind])).toBe(page);
            expect((await session.authenticator.credentials())[0].signCount, 'a fresh passkey proof')
                .toBeGreaterThan(signedIn);
        } finally {
            await session.close();
        }
    });
}

test('a passkey confirmed on the manage page and left open doesn\'t open the helpdesk', async ({ browser }) => {
    const session = await Session.open(browser, agent, env.contracts.manage);
    try {
        expect(await session.driveTo(['manage'])).toBe('manage');
        const confirmed = (await session.authenticator.credentials())[0].signCount;

        // Without finishing the manage page, the helpdesk contract in the same browser session
        await session.page.goto(`/nidp/jsp/main.jsp?id=${encodeURIComponent(env.contracts.helpdesk)}&sid=0`);
        expect(await session.driveTo(['helpdesk'])).toBe('helpdesk');
        expect((await session.authenticator.credentials())[0].signCount, 'a fresh passkey proof')
            .toBeGreaterThan(confirmed);
    } finally {
        await session.close();
    }
});
