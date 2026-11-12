import { expect, test } from '@playwright/test';
import { loadPasskey } from '../lib/authenticator';
import { type Account, env } from '../lib/env';
import { expectLog, expectNoLog, logMark, passkeyLines } from '../lib/idpLog';
import { msg } from '../lib/messages';
import { type Kind, Session } from '../lib/nam';

/**
 * Signing in with only a passkey (LOGIN mode). No password is checked there, so the class runs the
 * directory's login policy itself; a disabled account must be refused even with a valid passkey.
 */
test.describe.configure({ mode: 'serial' });

let user: Account;
let disabled: Account | undefined;

function re(text: string): RegExp {
    return new RegExp(text);
}

const DISABLED_SETUP = 'Enable the account, run `npm test -- -g "software passkey"` so it enrolls one, then disable it again.';

/**
 * The namapp1 directory sometimes times out a read, and the page then says "try again" without
 * reaching the passkey checks at all. Up to two retries, a few seconds apart, keep that from hiding
 * the result; they're noted in the report.
 */
async function withDirectoryRetry(session: Session, attempt: () => Promise<Kind>): Promise<Kind> {
    let kind = await attempt();
    // A pooled connection that has died can fail again at once, so wait a little before each retry
    for (let retry = 1; retry <= 2 && kind === 'login' && (await session.message()) === msg('error.tryAgain'); retry++) {
        test.info().annotations.push({ type: 'retried', description: `the directory timed out a read; retry ${retry}` });
        await session.page.waitForTimeout(5_000);
        kind = await attempt();
    }
    return kind;
}

/** ID first: the "Signing in as" page asks for the passkey by itself and leaves once the server has answered. */
async function signInWithId(session: Session, id: string): Promise<Kind> {
    await session.page.fill('#pk_userid', id);
    expect(await session.click('#pk_continue')).toBe('login');
    await session.page.waitForSelector('#pk_reset', { state: 'detached', timeout: 30_000 });
    return session.kind();
}

test.beforeAll(() => {
    user = env.user();
    disabled = env.disabled();
});

test('the passwordless accounts have a software passkey', async ({ browser }) => {
    await Session.enroll(browser, user, env.contracts.manage);
    if (disabled && !loadPasskey(disabled.id)) {
        if (!disabled.password) {
            throw new Error(`Set E2E_DISABLED_PASSWORD so ${disabled.id} can enroll. ${DISABLED_SETUP}`);
        }
        try {
            await Session.enroll(browser, disabled, env.contracts.manage);
        } catch (error) {
            throw new Error(`${disabled.id} couldn't enroll: ${(error as Error).message}\n${DISABLED_SETUP}`);
        }
    }
});

test('an enabled account signs in with only its passkey', async ({ browser }) => {
    const mark = logMark();
    const session = await Session.open(browser, user, env.contracts.login);
    try {
        expect(await session.driveTo(['login'])).toBe('login');
        expect(await withDirectoryRetry(session, () => session.click('#pk_button'))).toBe('finished');
        await expectLog(mark, re(`Authenticated user ${user.logPattern}`));
        expectNoLog(mark, re(`Login policy (refused|check failed for) ${user.logPattern}`));
    } finally {
        await session.close();
    }
});

test('an enabled account signs in by picking its passkey from autofill', async ({ browser }) => {
    const mark = logMark();
    const session = await Session.open(browser, user, env.contracts.login, { autofill: true });
    try {
        // The software passkey answers the autofill request as soon as the page makes it
        expect(await session.kind()).toBe('login');
        await session.page.waitForSelector('#pk_userid', { state: 'detached', timeout: 30_000 });
        expect(await session.kind()).toBe('finished');
        await expectLog(mark, re(`Authenticated user ${user.logPattern}`));
        // Exactly one sign-in, and no stray password page from a second post
        expect(passkeyLines(mark).filter(line => re(`Verified passkey .* for ${user.id}`).test(line)).length).toBe(1);
    } finally {
        await session.close();
    }
});

test('a disabled account is refused even with its passkey', async ({ browser }) => {
    test.skip(!disabled, 'set E2E_DISABLED_ID to run it');
    test.skip(!!disabled && !loadPasskey(disabled.id), `the disabled account has no software passkey yet. ${DISABLED_SETUP}`);
    const account = disabled!;
    const mark = logMark();
    const session = await Session.open(browser, account, env.contracts.login);
    try {
        // Without an ID first
        expect(await session.driveTo(['login'])).toBe('login');
        expect(await withDirectoryRetry(session, () => session.click('#pk_button'))).toBe('login');
        expect(await session.message()).toBe(msg('error.loginFailed'));

        // With the ID first
        expect(await withDirectoryRetry(session, () => signInWithId(session, account.id))).toBe('login');
        expect(await session.message()).toBe(msg('error.loginFailed'));

        // Refused by the class's own check of loginDisabled, once per attempt
        const refused = re(`Login policy refused ${account.logPattern} \\(account disabled\\)`);
        await expectLog(mark, refused);
        expect(passkeyLines(mark).filter(line => refused.test(line)).length, 'refusals logged, one per attempt').toBe(2);
        expectNoLog(mark, re(`Authenticated user ${account.logPattern}`));
    } finally {
        await session.close();
    }
});
