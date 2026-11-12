import { type Browser, expect, test } from '@playwright/test';
import { Authenticator, loadPasskey, savePasskey, type StoredCredential } from '../lib/authenticator';
import { type Account, env } from '../lib/env';
import { msg } from '../lib/messages';
import { type Kind, Session } from '../lib/nam';

/**
 * Keeping password managers in sync (SIGNAL_PASSWORD_MANAGERS=true on the class). Chrome's virtual
 * authenticators stand in for the password manager: Chrome deletes a credential from them when a page
 * says the site no longer has it, so the tests check what the browser actually did.
 *
 * Like a real one, an authenticator keeps one passkey per account per site, and the server lists the
 * account's passkeys when a new one is made, so the browser won't make a second one beside the first.
 * The account's own passkey is saved and taken out first; where a test needs both, it goes on a
 * second, USB, authenticator in the same browser.
 *
 * Skipped when the class has the setting off, which shows as a manage page with no signals.
 */
test.describe.configure({ mode: 'serial' });

const PREFIX = 'e2e-signal';
let user: Account;

test.beforeAll(() => {
    user = env.user();
});

/** The manage page, with its signals switched on and the browser able to pass them on. */
async function openManage(browser: Browser): Promise<Session> {
    const session = await Session.open(browser, user, env.contracts.manage);
    expect(await session.driveTo(['manage'])).toBe('manage');
    const supported = await session.page.evaluate(
        () => typeof (PublicKeyCredential as unknown as Record<string, unknown>).signalUnknownCredential === 'function');
    if (!supported || (await session.page.locator('#pk_signal').count()) === 0) {
        await session.close();
        test.skip(true, supported ? 'SIGNAL_PASSWORD_MANAGERS is off on the class: the manage page carried no signals'
            : 'This Chrome has no WebAuthn Signals API');
    }
    return session;
}

/** Saves the account's passkey as it is now, before a new one replaces it in this browser. */
async function keepPasskey(session: Session): Promise<StoredCredential> {
    const id = loadPasskey(user.id)!.credentialId;
    const current = (await session.authenticator.credentials()).find(c => c.credentialId === id);
    if (!current) {
        throw new Error(`The browser doesn't hold ${user.id}'s passkey`);
    }
    savePasskey(user.id, current);
    return current;
}

/** Adds a passkey on the manage page and returns it; the browser held the account's own, now saved, before. */
async function addPasskey(session: Session, name: string): Promise<StoredCredential> {
    for (const held of await session.authenticator.credentials()) {
        await session.authenticator.remove(held.credentialId);
    }
    const before = new Set<string>();
    await session.click('#pk_add');
    expect(await session.driveTo(['manage'], { passkeyName: name })).toBe('manage');
    const added = (await session.authenticator.credentials()).filter(c => !before.has(c.credentialId));
    expect(added, 'one new passkey in the browser').toHaveLength(1);
    return added[0];
}

/** The passkey-only page's button, again if the directory timed out a read, as namapp1's sometimes does. */
async function signInWithButton(session: Session): Promise<Kind> {
    let kind = await session.click('#pk_button');
    for (let retry = 1; retry <= 2 && kind === 'login' && (await session.message()) === msg('error.tryAgain'); retry++) {
        test.info().annotations.push({ type: 'retried', description: `the directory timed out a read; retry ${retry}` });
        await session.page.waitForTimeout(5_000);
        kind = await session.click('#pk_button');
    }
    return kind;
}

test('the account has a software passkey', async ({ browser }) => {
    await Session.enroll(browser, user, env.contracts.manage);
    // Leftovers from an earlier run that stopped partway
    const session = await Session.open(browser, user, env.contracts.manage);
    try {
        expect(await session.driveTo(['manage'])).toBe('manage');
        await session.removePasskeysNamed(PREFIX);
    } finally {
        await session.close();
    }
});

test('removing a passkey on the manage page removes it from the password manager, and only that one', async ({ browser }) => {
    const session = await openManage(browser);
    try {
        const kept = await keepPasskey(session);
        const added = await addPasskey(session, `${PREFIX}-manage`);
        const key = await Authenticator.attach(session.page, 'usb');
        await key.add(kept);

        await session.removePasskeysNamed(`${PREFIX}-manage`);

        expect(await session.authenticator.waitUntilGone(added.credentialId),
            'the removed passkey is gone from the browser').toBe(true);
        // Give the list of passkeys still registered time to arrive too: it must leave this one alone
        await session.page.waitForTimeout(2_000);
        expect((await key.credentials()).map(c => c.credentialId), 'the passkey the user still has stays')
            .toContain(kept.credentialId);
    } finally {
        await session.close();
    }
});

test('a passkey removed elsewhere is forgotten when it fails to sign in', async ({ browser }) => {
    // A second passkey, kept as the browser holds it
    const adding = await openManage(browser);
    let removed: StoredCredential;
    try {
        await keepPasskey(adding);
        removed = await addPasskey(adding, `${PREFIX}-login`);
    } finally {
        await adding.close();
    }

    // Removed from another browser, so the one holding it is never told
    const elsewhere = await Session.open(browser, user, env.contracts.manage);
    try {
        expect(await elsewhere.driveTo(['manage'])).toBe('manage');
        await elsewhere.removePasskeysNamed(`${PREFIX}-login`);
    } finally {
        await elsewhere.close();
    }

    // A browser holding only the removed passkey offers it on the passkey-only page
    const session = await Session.open(browser, user, env.contracts.login);
    try {
        await session.authenticator.remove(loadPasskey(user.id)!.credentialId);
        await session.authenticator.add(removed);
        expect(await session.driveTo(['login'])).toBe('login');

        expect(await signInWithButton(session)).toBe('login');
        expect(await session.message()).toBe(msg('error.loginFailed'));
        expect(await session.authenticator.waitUntilGone(removed.credentialId),
            'the browser forgot the passkey the site no longer has').toBe(true);
    } finally {
        await session.close();
    }
});
