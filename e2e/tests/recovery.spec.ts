import { randomInt } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { loadPasskey } from '../lib/authenticator';
import { type Account, env } from '../lib/env';
import { countValuesInLog, expectLog, expectNoLog, logMark } from '../lib/idpLog';
import { countValuesInMail, expectMail, mailMark, userMail } from '../lib/mail';
import { msg } from '../lib/messages';
import { Session, seenSecrets } from '../lib/nam';

/**
 * Recovery and helpdesk, end to end against the test Identity Server. The tests run in order and
 * share what they issue: the token from the helpdesk test is used by the token tests, and so on.
 */
test.describe.configure({ mode: 'serial' });

const RECOVERED = 'e2e-recovered';

let agent: Account;
let user: Account;
let runMark: number;
let runMailMark = 0;
let token: string | undefined;
let recoveredAt = 0;
let codes: string[] = [];

function re(text: string): RegExp {
    return new RegExp(text);
}

function wrongCode(): string {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let code = '';
    for (let i = 0; i < 16; i++) {
        code += alphabet[randomInt(alphabet.length)];
    }
    return code.replace(/(.{4})(?=.)/g, '$1-');
}

async function enterCode(session: Session, code: string) {
    await session.page.fill('#pk_code', code);
    return session.click('#pk_button');
}

/** Password, then the code, then a new passkey, then the list, where the new passkey is removed again. */
async function recoverWith(session: Session, code: string, kind: 'recovery code' | 'helpdesk token', mark: number) {
    const mailFrom = await mailMark();
    expect(await session.driveTo(['recovery'])).toBe('recovery');
    // Someone recovering has lost their passkey, so this browser doesn't hold it. If it did, the browser
    // would refuse to create another for the same account, since the server lists the ones it has
    await session.authenticator.remove(loadPasskey(session.account.id)!.credentialId);
    expect(await enterCode(session, code)).toBe('register');
    expect(await session.driveTo(['manage'], { passkeyName: RECOVERED })).toBe('manage');
    expect(await session.message()).toBe(msg('manage.added'));
    // Someone else may have recovered first, so the list asks for a review, and a cool-down holds back new codes
    await expect(session.page.locator('#pk_review')).toHaveText(msg('manage.review'));
    await expect(session.page.locator('.pk-manage-table')).toContainText(msg('manage.viaRecovery'));
    if (env.recoveryCooldownSec > 0) {
        await expect(session.page.locator('#pk_codes')).toHaveCount(0);
        await expect(session.page.locator('#pk_codes_wait')).toBeVisible();
    }
    recoveredAt = Date.now();
    await session.removePasskeysNamed(RECOVERED);
    expect(await session.driveTo(['finished'])).toBe('finished');
    await expectLog(mark,
        re(`Account recovery started for ${user.logPattern} with a ${kind}`),
        re(`Account recovery finished for ${user.logPattern}`),
        re(`Authenticated user ${user.logPattern}`));
    if (userMail()) {
        await expectMail(mailFrom, userMail()!,
            msg(kind === 'recovery code' ? 'notify.recoveredCode.subject' : 'notify.recoveredToken.subject'),
            msg('notify.added.subject'), msg('notify.removed.subject'));
    }
}

async function expectRefusedCode(session: Session, code: string, mark: number) {
    expect(await session.driveTo(['recovery'])).toBe('recovery');
    expect(await enterCode(session, code)).toBe('recovery');
    expect(await session.message()).toBe(msg('error.recoveryCode'));
    await expectLog(mark, re(`Wrong recovery code for ${user.logPattern} \\(1 of ${env.maxFailed}\\)`));
}

test.beforeAll(async () => {
    agent = env.agent();
    user = env.user();
    runMark = logMark();
    runMailMark = await mailMark();
});

test('both test accounts have a software passkey', async ({ browser }) => {
    await Session.enroll(browser, agent, env.contracts.manage);
    await Session.enroll(browser, user, env.contracts.manage);
});

test('helpdesk refuses someone outside the group', async ({ browser }) => {
    const mark = logMark();
    const session = await Session.open(browser, user, env.contracts.helpdesk);
    try {
        expect(await session.driveTo(['error'])).toBe('error');
        expect(await session.text()).toContain(msg('error.notHelpdesk'));
        await expectLog(mark, re(`Refused helpdesk access for ${user.logPattern}`));
    } finally {
        await session.close();
    }
});

test('helpdesk needs every check, refuses the agent\'s own account, then issues a token', async ({ browser }) => {
    const mark = logMark();
    const mailFrom = await mailMark();
    const session = await Session.open(browser, agent, env.contracts.helpdesk);
    try {
        expect(await session.driveTo(['helpdesk'])).toBe('helpdesk');
        const { page } = session;

        await page.fill('#pk_target', user.id);
        await page.check('input[name=pk_check1]');
        await page.check('input[name=pk_check2]');
        expect(await session.click('#pk_issue')).toBe('helpdesk');
        expect(await session.message()).toBe(msg('error.helpdeskChecks'));

        await page.fill('#pk_target', agent.id);
        for (const n of [1, 2, 3]) {
            await page.check(`input[name=pk_check${n}]`);
        }
        expect(await session.click('#pk_issue')).toBe('helpdesk');
        expect(await session.message()).toBe(msg('error.helpdeskSelf'));
        await expectLog(mark, re(`Refused helpdesk token: ${agent.logPattern} asked for their own account`));
        expectNoLog(mark, re(`issued a token for ${agent.logPattern}`));

        await page.fill('#pk_target', user.id);
        for (const n of [1, 2, 3]) {
            await page.check(`input[name=pk_check${n}]`);
        }
        expect(await session.click('#pk_issue')).toBe('helpdesk');
        token = await session.readIssuedToken();
        expect(token).toMatch(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/);
        await expectLog(mark, re(`Helpdesk agent ${agent.logPattern} issued a token for ${user.logPattern}`));
        if (userMail()) {
            await expectMail(mailFrom, userMail()!, msg('notify.tokenIssued.subject'));
        }

        expect(await session.click('#pk_done')).toBe('finished');
        await expectLog(mark, re(`Authenticated user ${agent.logPattern}`));
    } finally {
        await session.close();
    }
});

test('the helpdesk token recovers the account', async ({ browser }) => {
    test.skip(!token, 'needs the token from the helpdesk test');
    const mark = logMark();
    const session = await Session.open(browser, user, env.contracts.recovery);
    try {
        await recoverWith(session, token!, 'helpdesk token', mark);
    } finally {
        await session.close();
    }
});

test('the helpdesk token works only once', async ({ browser }) => {
    test.skip(!token, 'needs the token from the helpdesk test');
    const mark = logMark();
    const session = await Session.open(browser, user, env.contracts.recovery);
    try {
        await expectRefusedCode(session, token!, mark);
    } finally {
        await session.close();
    }
});

test('new recovery codes can be created from the list', async ({ browser }) => {
    // The token recovery just started a cool-down; new codes are refused until it's over
    const wait = recoveredAt + env.recoveryCooldownSec * 1000 + 2000 - Date.now();
    if (env.recoveryCooldownSec > 0 && recoveredAt > 0 && wait > 0) {
        await new Promise(resolve => setTimeout(resolve, wait));
    }
    const mark = logMark();
    const mailFrom = await mailMark();
    const session = await Session.open(browser, user, env.contracts.manage);
    try {
        expect(await session.driveTo(['manage'])).toBe('manage');
        // Tidies up after an earlier run that stopped part way
        await session.removePasskeysNamed(RECOVERED);
        expect(await session.click('#pk_codes')).toBe('codes');
        codes = await session.readCodes();
        expect(codes.length).toBeGreaterThan(1);
        for (const code of codes) {
            expect(code).toMatch(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/);
        }
        expect(await session.click('#pk_done')).toBe('manage');
        expect(await session.text()).toContain(`${msg('codes.manageLeft')} ${codes.length}.`);
        expect(await session.driveTo(['finished'])).toBe('finished');
        await expectLog(mark, re(`New recovery codes generated for ${user.logPattern}`));
        if (userMail()) {
            await expectMail(mailFrom, userMail()!, msg('notify.codes.subject'));
        }
    } finally {
        await session.close();
    }
});

test('a recovery code recovers the account', async ({ browser }) => {
    test.skip(codes.length === 0, 'needs the codes from the previous test');
    const mark = logMark();
    const session = await Session.open(browser, user, env.contracts.recovery);
    try {
        await recoverWith(session, codes[0], 'recovery code', mark);
    } finally {
        await session.close();
    }
});

test('a recovery code works only once', async ({ browser }) => {
    test.skip(codes.length === 0, 'needs the codes from the earlier test');
    const mark = logMark();
    const session = await Session.open(browser, user, env.contracts.recovery);
    try {
        await expectRefusedCode(session, codes[0], mark);
    } finally {
        await session.close();
    }
});

test(`${env.maxFailed} wrong codes end the attempt`, async ({ browser }) => {
    const mark = logMark();
    const session = await Session.open(browser, user, env.contracts.recovery);
    try {
        expect(await session.driveTo(['recovery'])).toBe('recovery');
        for (let attempt = 1; attempt < env.maxFailed; attempt++) {
            expect(await enterCode(session, wrongCode())).toBe('recovery');
            expect(await session.message()).toBe(msg('error.recoveryCode'));
        }
        expect(await enterCode(session, wrongCode())).toBe('error');
        expect(await session.text()).toContain(msg('error.tooManyAttempts'));
        await expectLog(mark, re(`Wrong recovery code for ${user.logPattern} \\(${env.maxFailed} of ${env.maxFailed}\\)`));
        expectNoLog(mark, re(`Account recovery started for ${user.logPattern}`));
    } finally {
        await session.close();
    }
});

test('no code, token or password reached the log or an email', async () => {
    const secrets = countValuesInLog(runMark, seenSecrets);
    expect(secrets, 'log lines containing a recovery code or helpdesk token').toBe(0);
    const passwords = countValuesInLog(runMark, [agent.password, user.password]);
    expect(passwords, 'log lines containing a test account password').toBe(0);
    if (userMail()) {
        expect(await countValuesInMail(runMailMark, seenSecrets), 'emails containing a recovery code or helpdesk token').toBe(0);
    }
});
