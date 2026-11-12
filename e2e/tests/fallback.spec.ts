import { expect, test } from '@playwright/test';
import { env } from '../lib/env';
import { msg } from '../lib/messages';
import { Session } from '../lib/nam';

/**
 * "Use another way to sign in" on the passwordless page. It goes to FALLBACK_CONTRACT_URL, or to NAM's
 * default contract when that isn't set, and must lead off the passkey page. PASSKEY_ONLY on a method
 * hides it: a second LOGIN contract with that set must not offer it anywhere on the page.
 * Nothing is signed in to, and no password is typed.
 */
test.describe.configure({ mode: 'serial' });

let fallbackHref: string | undefined;

/**
 * The passwordless page, without answering anything: NAM shows its default contract for an ID it
 * doesn't know, and that page must not be signed in to here.
 */
async function expectLoginPage(session: Session, contract: string) {
    const kind = await session.kind();
    expect(kind, `${contract} didn't open the passwordless page, so NAM showed its default contract. Use the `
        + `ID on the contract's Authentication Card tab, not its name or URI`).toBe('login');
}

function htmlEscaped(text: string): string {
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

test('the passwordless page offers a fallback', async ({ browser }) => {
    const session = await Session.open(browser, env.user(), env.contracts.login);
    try {
        await expectLoginPage(session, env.contracts.login);
        const link = session.page.getByRole('link', { name: msg('fallback.link') });
        test.skip((await link.count()) === 0,
            `${env.contracts.login} shows no fallback link: it's NAM's default contract, or its method has PASSKEY_ONLY=true`);
        await expect(link).toHaveCount(1);
        fallbackHref = (await link.getAttribute('href')) ?? undefined;
        expect(fallbackHref).toBeTruthy();
    } finally {
        await session.close();
    }
});

test('the fallback leads to another sign-in page, not back to the passkey', async ({ browser }) => {
    test.skip(!fallbackHref, 'needs the fallback link from the previous test');
    const session = await Session.open(browser, env.user(), env.contracts.login);
    try {
        await expectLoginPage(session, env.contracts.login);
        // Stops on whatever page the fallback opens; NAM's default contract is usually Name/Password
        const kind = await session.click(`text=${msg('fallback.link')}`);
        expect(kind, `the fallback (${fallbackHref}) opened the ${kind} page`).toBe('password');
    } finally {
        await session.close();
    }
});

test('a PASSKEY_ONLY method offers no fallback', async ({ browser }) => {
    test.skip(!env.contracts.passkeyOnly, 'set E2E_CONTRACT_PASSKEY_ONLY to a LOGIN contract whose method has PASSKEY_ONLY=true');
    test.skip(!fallbackHref, 'needs the fallback link from the previous test');
    const session = await Session.open(browser, env.user(), env.contracts.passkeyOnly!);
    try {
        await expectLoginPage(session, env.contracts.passkeyOnly!);
        await expect(session.page.getByRole('link', { name: msg('fallback.link') })).toHaveCount(0);
        // Not just hidden: the address mustn't be anywhere in the page
        const html = await session.page.content();
        expect(html).not.toContain(fallbackHref!);
        expect(html).not.toContain(htmlEscaped(fallbackHref!));
        // It's still a passkey sign-in page
        await expect(session.page.locator('#pk_button, #pk_continue').first()).toBeVisible();
    } finally {
        await session.close();
    }
});
