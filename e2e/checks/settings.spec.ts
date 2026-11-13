import fs from 'node:fs';
import path from 'node:path';
import { expect, test } from '@playwright/test';
import { loadPasskey, savePasskey } from '../lib/authenticator';
import { type Account, env } from '../lib/env';
import { expectLog, expectNoLog, logMark } from '../lib/idpLog';
import { msg } from '../lib/messages';
import { Session } from '../lib/nam';

/**
 * Settings that the browser tests leave at their defaults, checked one Admin Console setup at a time.
 * Choose the group with E2E_CHECK:
 *
 * - prepare: with recovery codes on, keeps one real code in e2e/.state (gitignored) for the next group.
 * - passwordfetch: a contract of the LOGIN method then PasswordFetch; see the test.
 * - settings: needs, on the test Identity Server,
 *     the class:         RECOVERY_CODES=false
 *     the LOGIN method:  ACCOUNT_CHECK=verify-rights
 *     the MANAGE method: ALLOWED_AAGUIDS and ATTESTATION_TRUST_ROOTS (any real vendor root)
 *     the gated method:  ENROLL_GATES=helpdesk
 *
 * Put the settings back afterwards: the browser tests expect the defaults.
 */
test.describe.configure({ mode: 'serial' });

const CHECK = process.env.E2E_CHECK ?? '';
const CODE_FILE = path.join(__dirname, '../.state/check-recovery-code.json');

let user: Account;
let agent: Account;

function re(text: string): RegExp {
    return new RegExp(text);
}

test.beforeAll(() => {
    user = env.user();
    agent = env.agent();
});

/** The agent issues a helpdesk token for an account, from the helpdesk contract. */
async function issueToken(browser: import('@playwright/test').Browser, target: string): Promise<string> {
    const session = await Session.open(browser, agent, env.contracts.helpdesk);
    try {
        expect(await session.driveTo(['helpdesk'])).toBe('helpdesk');
        await session.page.fill('#pk_target', target);
        for (const n of [1, 2, 3]) {
            await session.page.check(`input[name=pk_check${n}]`);
        }
        expect(await session.click('#pk_issue')).toBe('helpdesk');
        return await session.readIssuedToken();
    } finally {
        await session.close();
    }
}

test.describe('prepare', () => {
    test.skip(CHECK !== 'prepare', 'E2E_CHECK=prepare');

    test('keep one real recovery code for the codes-off check', async ({ browser }) => {
        const session = await Session.open(browser, user, env.contracts.manage);
        try {
            expect(await session.driveTo(['manage'])).toBe('manage');
            if (await session.page.locator('#pk_codes_wait').count()) {
                await session.page.waitForTimeout((env.recoveryCooldownSec + 5) * 1000);
                await session.page.reload();
                expect(await session.driveTo(['manage'])).toBe('manage');
            }
            expect(await session.click('#pk_codes')).toBe('codes');
            const codes = await session.readCodes();
            fs.mkdirSync(path.dirname(CODE_FILE), { recursive: true, mode: 0o700 });
            fs.writeFileSync(CODE_FILE, JSON.stringify({ code: codes[0] }), { mode: 0o600 });
            expect(await session.click('#pk_done')).toBe('manage');
        } finally {
            await session.close();
        }
    });
});

test.describe('passwordfetch', () => {
    test.skip(CHECK !== 'passwordfetch', 'E2E_CHECK=passwordfetch');

    // A contract (E2E_CONTRACT_PASSWORD_FETCH, its card ID) of the LOGIN method, then NAM's PasswordFetch
    // method with Retain Previous Principal on and Ignore Password Retrieval Failure off, on an
    // eDirectory user store whose Universal Password policy lets the admin retrieve passwords
    test('PasswordFetch after a passkey-only sign-in keeps the passkey user and finishes', async ({ browser }) => {
        const contract = process.env.E2E_CONTRACT_PASSWORD_FETCH?.trim() || 'PkTestPasswordFetch';
        const mark = logMark();
        const session = await Session.open(browser, user, contract);
        try {
            expect(await session.driveTo(['login'])).toBe('login');
            expect(await session.click('#pk_button')).toBe('finished');
            expect(await session.text()).toContain(user.id);
            await expectLog(mark, re(`Authenticated user ${user.logPattern}`));
            await expectLog(mark, re(`Password Fetch Class: Principal username is : ${user.logPattern}`));
            await expectLog(mark, /Authentication method \S+ succeeded/);
        } finally {
            await session.close();
        }
    });
});

test.describe('settings', () => {
    test.skip(CHECK !== 'settings', 'E2E_CHECK=settings');

    test('RECOVERY_CODES=false: no codes anywhere, an old code is refused, a helpdesk token recovers', async ({ browser }) => {
        test.skip(!fs.existsSync(CODE_FILE), 'run E2E_CHECK=prepare first, with recovery codes on');
        const oldCode = JSON.parse(fs.readFileSync(CODE_FILE, 'utf8')).code as string;

        // The manage page doesn't mention codes
        const manage = await Session.open(browser, user, env.contracts.manage);
        try {
            expect(await manage.driveTo(['manage'])).toBe('manage');
            await expect(manage.page.locator('#pk_codes')).toHaveCount(0);
            expect(await manage.text()).not.toContain(msg('codes.manageLeft'));
        } finally {
            await manage.close();
        }

        // The recovery page asks only for a helpdesk code, and refuses a code issued before
        let mark = logMark();
        const refused = await Session.open(browser, user, env.contracts.recovery);
        try {
            expect(await refused.driveTo(['recovery'])).toBe('recovery');
            expect(await refused.text()).toContain(msg('recovery.introHelpdesk'));
            await expect(refused.page.locator('#pk_code')).toHaveAttribute('placeholder', msg('recovery.placeholderHelpdesk'));
            await refused.page.fill('#pk_code', oldCode);
            expect(await refused.click('#pk_button')).toBe('recovery');
            expect(await refused.message()).toBe(msg('error.recoveryCode'));
            await expectLog(mark, re(`Wrong recovery code for ${user.logPattern} \\(1 of `));
        } finally {
            await refused.close();
        }
        fs.rmSync(CODE_FILE, { force: true });

        // A helpdesk token still recovers the account
        const token = await issueToken(browser, user.id);
        mark = logMark();
        const recovering = await Session.open(browser, user, env.contracts.recovery);
        try {
            expect(await recovering.driveTo(['recovery'])).toBe('recovery');
            await recovering.authenticator.remove(loadPasskey(user.id)!.credentialId);
            await recovering.page.fill('#pk_code', token);
            expect(await recovering.click('#pk_button')).toBe('register');
            expect(await recovering.driveTo(['manage'], { passkeyName: 'e2e-check-recovered' })).toBe('manage');
            await expect(recovering.page.locator('#pk_codes')).toHaveCount(0);
            await recovering.removePasskeysNamed('e2e-check-recovered');
            expect(await recovering.driveTo(['finished'])).toBe('finished');
            await expectLog(mark, re(`Account recovery started for ${user.logPattern} with a helpdesk token`));
        } finally {
            await recovering.close();
        }
    });

    test('ACCOUNT_CHECK=verify-rights: an enabled account signs in, a disabled one is refused', async ({ browser }) => {
        const mark = logMark();
        const session = await Session.open(browser, user, env.contracts.login);
        try {
            expect(await session.driveTo(['login'])).toBe('login');
            expect(await session.click('#pk_button')).toBe('finished');
            await expectLog(mark, re(`Authenticated user ${user.logPattern}`));
            expectNoLog(mark, re('the user store.s proxy account can.t read|Can.t check the right'));
        } finally {
            await session.close();
        }
        const disabled = env.disabled();
        if (disabled) {
            const refusedMark = logMark();
            const refused = await Session.open(browser, disabled, env.contracts.login);
            try {
                expect(await refused.driveTo(['login'])).toBe('login');
                expect(await refused.click('#pk_button')).toBe('login');
                await expectLog(refusedMark, re(`Login policy refused ${disabled.logPattern} \\(account disabled\\)`));
            } finally {
                await refused.close();
            }
        }
    });

    test('allow-list: an authenticator without trusted attestation is refused', async ({ browser }) => {
        const mark = logMark();
        const session = await Session.open(browser, user, env.contracts.manage);
        try {
            expect(await session.driveTo(['manage'])).toBe('manage');
            // Keep the account's own passkey; the browser would otherwise refuse to make a second one
            const own = (await session.authenticator.credentials()).find(c => c.credentialId === loadPasskey(user.id)!.credentialId)!;
            savePasskey(user.id, own);
            await session.authenticator.remove(own.credentialId);

            expect(await session.click('#pk_add')).toBe('register');
            await session.page.fill('#pk_name', 'e2e-check-allowlist');
            await session.page.click('#pk_button');
            await expect(session.page.locator('#pk_msg')).toHaveText(msg('error.authenticatorNotAllowed'), { timeout: 30_000 });
            await expectLog(mark, re('Refused authenticator [0-9a-f]{32}'));
            await expect(session.page.locator('.pk-remove[data-name="e2e-check-allowlist"]')).toHaveCount(0);
        } finally {
            await session.close();
        }
    });

    test('ENROLL_GATES=helpdesk: a first passkey needs a helpdesk token, and no codes are shown', async ({ browser }) => {
        const account = env.enroll();
        test.skip(!env.contracts.gated || !account, 'set E2E_CONTRACT_GATED, E2E_ENROLL_ID and E2E_ENROLL_PASSWORD');
        const token = await issueToken(browser, account!.id);
        const mark = logMark();
        const session = await Session.open(browser, account!, env.contracts.gated!);
        try {
            expect(await session.driveTo(['gate'])).toBe('gate');
            await session.page.fill('#pk_gate_code', 'AAAA-BBBB-CCCC-DDDD');
            expect(await session.click('#pk_button')).toBe('gate');
            expect(await session.message()).toBe(msg('error.gateCode'));

            await session.page.fill('#pk_gate_code', token);
            expect(await session.click('#pk_button')).toBe('register');
            await session.page.fill('#pk_name', 'e2e-check-gate');
            // With RECOVERY_CODES=false the first passkey goes straight to the list, with no codes page
            expect(await session.click('#pk_button')).toBe('manage');
            await expect(session.page.locator('#pk_codes')).toHaveCount(0);
            await session.removePasskeysNamed('e2e-check-gate');
            await expect(session.page.locator('.pk-manage-table')).toHaveCount(0);
            await expectLog(mark, re(`First-passkey check HELPDESK passed for ${account!.logPattern}`));
        } finally {
            await session.context.close();
        }
    });
});
