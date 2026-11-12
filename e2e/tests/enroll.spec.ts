import { expect, test } from '@playwright/test';
import { type Account, env } from '../lib/env';
import { expectLog, expectNoLog, logMark } from '../lib/idpLog';
import { mailMark, readMail } from '../lib/mail';
import { msg } from '../lib/messages';
import { Session } from '../lib/nam';

/**
 * ENROLL_GATES=email: before a first passkey the user must enter a code emailed to them. Needs a
 * MANAGE contract with that set (E2E_CONTRACT_GATED), an account with no passkey (E2E_ENROLL_ID) and
 * its mail value (E2E_ENROLL_MAIL). The passkey made here is removed again, so the account is ready
 * for the next run.
 */
test.describe.configure({ mode: 'serial' });

const NAME = 'e2e-gated';

function re(text: string): RegExp {
    return new RegExp(text);
}

async function emailedCode(mark: number, address: string): Promise<string> {
    const body = await readMail(mark, address, msg('notify.enrollCode.subject'));
    const code = body.match(/\b(\d{6})\b/)?.[1];
    expect(code, 'a six-digit code in the email').toBeTruthy();
    return code!;
}

test('a first passkey needs the code emailed to the user', async ({ browser }) => {
    const account: Account | undefined = env.enroll();
    const address = env.enrollMail();
    test.skip(!env.contracts.gated || !account || !address,
        'set E2E_CONTRACT_GATED, E2E_ENROLL_ID, E2E_ENROLL_PASSWORD and E2E_ENROLL_MAIL');
    const mark = logMark();
    const mailFrom = await mailMark();
    const session = await Session.open(browser, account!, env.contracts.gated!);
    try {
        expect(await session.driveTo(['gate'])).toBe('gate');
        expect(await session.text()).toContain(msg('gate.emailIntro').split('{address}')[0]);
        const first = await emailedCode(mailFrom, address!);

        // A new code replaces the first one
        const beforeResend = await mailMark();
        expect(await session.click('#pk_resend')).toBe('gate');
        expect(await session.message()).toBe(msg('gate.sent'));
        const second = await emailedCode(beforeResend, address!);

        const wrong = first === second ? String((Number(second) + 1) % 1_000_000).padStart(6, '0') : first;
        await session.page.fill('#pk_gate_code', wrong);
        expect(await session.click('#pk_button')).toBe('gate');
        expect(await session.message()).toBe(msg('error.gateCode'));

        await session.page.fill('#pk_gate_code', second);
        expect(await session.click('#pk_button')).toBe('register');
        expect(await session.driveTo(['manage'], { passkeyName: NAME })).toBe('manage');
        await session.removePasskeysNamed(NAME);
        await expect(session.page.locator('.pk-manage-table')).toHaveCount(0);

        await expectLog(mark,
            re(`Emailing a first-passkey setup code to ${account!.logPattern} \\(1 of 5\\)`),
            re(`Wrong setup code for ${account!.logPattern} \\(1 of ${env.maxFailed}\\)`),
            re(`First-passkey check EMAIL passed for ${account!.logPattern}`),
            re(`Registered passkey '${NAME}`));
        // Six digits can turn up by chance anywhere in NAM's log, so this checks the passkey lines
        expectNoLog(mark, re(`\\b(${first}|${second})\\b`));
    } finally {
        await session.close();
    }
});
