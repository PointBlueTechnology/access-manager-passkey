import { test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { Authenticator, loadPasskey, savePasskey } from './authenticator';
import { type Account, env } from './env';
import { errorTexts } from './messages';

/** Which page of a contract the browser is on. */
export type Kind =
    | 'password' // the stock Name/Password form
    | 'login' // passkey_login.jsp: sign in with only a passkey
    | 'mfa' // passkey_mfa.jsp: confirm with a passkey
    | 'register' // passkey_register.jsp: create a passkey
    | 'saved' // passkey_register.jsp after saving
    | 'codes' // passkey_codes.jsp
    | 'manage' // passkey_manage.jsp
    | 'recovery' // passkey_recovery.jsp
    | 'gate' // passkey_gate.jsp: a code before the first passkey
    | 'helpdesk' // passkey_helpdesk.jsp
    | 'error' // NAM's error page showing one of the class's errors
    | 'finished'; // none of the above for a while: the contract has finished, or NAM showed something else

const STEP_TIMEOUT = 30_000;
const FINISHED_AFTER = 6_000;

/** Codes and tokens seen during the run, kept in memory only, to check that none reached the log. */
export const seenSecrets: string[] = [];

export class Session {
    private constructor(
        readonly account: Account,
        readonly context: BrowserContext,
        readonly page: Page,
        readonly authenticator: Authenticator,
        private readonly passkeyId: string | undefined,
    ) {}

    /** A fresh browser session, with the account's software passkey, at the start of a contract. */
    static async open(browser: Browser, account: Account, contract: string,
            options: { autofill?: boolean } = {}): Promise<Session> {
        const context = await browser.newContext({ baseURL: env.baseUrl });
        const page = await context.newPage();
        page.on('dialog', dialog => void dialog.accept());
        if (!options.autofill) {
            // The software passkey answers an autofill request at once, as if the user had picked it,
            // which would race whatever the test clicks; only the autofill test leaves it on
            await page.addInitScript(() => {
                if (window.PublicKeyCredential) {
                    PublicKeyCredential.isConditionalMediationAvailable = () => Promise.resolve(false);
                }
            });
        }
        const authenticator = await Authenticator.attach(page);
        const stored = loadPasskey(account.id);
        if (stored) {
            await authenticator.add(stored);
        }
        const session = new Session(account, context, page, authenticator, stored?.credentialId);
        await page.goto(`/nidp/jsp/main.jsp?id=${encodeURIComponent(contract)}&sid=0`);
        return session;
    }

    /** Keeps the passkey's signature counter current, since the server rejects one that goes back. */
    async close(): Promise<void> {
        try {
            if (this.passkeyId) {
                const current = (await this.authenticator.credentials()).find(c => c.credentialId === this.passkeyId);
                if (current) {
                    savePasskey(this.account.id, current);
                }
            }
        } finally {
            await this.context.close();
        }
    }

    async kind(): Promise<Kind> {
        const deadline = Date.now() + FINISHED_AFTER;
        while (Date.now() < deadline) {
            const kind = await detect(this.page);
            if (kind) {
                return kind;
            }
            await this.page.waitForTimeout(250);
        }
        return 'finished';
    }

    /** Runs an action that replaces the current page, and waits for the next one. */
    async act(action: () => Promise<void>): Promise<Kind> {
        await markCurrent(this.page);
        await action();
        await waitForReplacement(this.page);
        return this.kind();
    }

    async click(selector: string): Promise<Kind> {
        return this.act(() => this.page.click(selector));
    }

    async message(): Promise<string> {
        return (await this.page.locator('#pk_msg').innerText()).trim();
    }

    async text(): Promise<string> {
        return (await this.page.locator('body').innerText()).replace(/\s+/g, ' ').trim();
    }

    /**
     * Answers whatever the contract asks (password, passkey, new passkey, codes) until it reaches one
     * of the wanted pages, and fails on anything else.
     */
    async driveTo(wanted: Kind[], options: { passkeyName?: string } = {}): Promise<Kind> {
        let passwordTries = 0;
        for (let step = 0; step < 25; step++) {
            const kind = await this.kind();
            if (wanted.includes(kind)) {
                return kind;
            }
            switch (kind) {
                case 'password':
                    if (++passwordTries > 2) {
                        throw new Error(`Password sign-in failed for ${this.account.id}: ${await this.text()}`);
                    }
                    if (passwordTries === 2) {
                        // namapp1's pooled directory connection fails the first search after it has been
                        // idle for over 20 seconds, and NAM reports that as "Login failed". The password
                        // never reached the directory, so one more try costs nothing towards lockout.
                        test.info().annotations.push({ type: 'retried', description: `password sign-in for ${this.account.id}` });
                        await this.page.waitForTimeout(5_000);
                    }
                    await this.act(async () => {
                        await this.page.fill('#Ecom_User_ID', this.account.id);
                        await this.page.fill('#Ecom_Password', this.account.password);
                        await this.page.click('#loginButton2');
                    });
                    break;
                case 'mfa':
                    await this.confirmPasskey();
                    break;
                case 'register':
                    await this.act(async () => {
                        await this.page.fill('#pk_name', options.passkeyName ?? 'e2e');
                        await this.page.click('#pk_button');
                    });
                    break;
                case 'codes':
                    await this.readCodes();
                    await this.click('#pk_done');
                    break;
                case 'saved':
                    await this.click('#pk_continue');
                    break;
                case 'manage':
                    await this.click('#pk_done');
                    break;
                default:
                    throw new Error(`Expected ${wanted.join(' or ')} but reached ${kind}: ${(await this.text()).slice(0, 400)}`);
            }
        }
        throw new Error(`Gave up before reaching ${wanted.join(' or ')}`);
    }

    /** The MFA page starts the ceremony itself; the button is there if the browser wanted a click. */
    private async confirmPasskey(): Promise<void> {
        if ((await this.authenticator.credentials()).length === 0) {
            throw new Error(`${this.account.id} already has passkeys, but none this script holds. `
                + `Clear the account's passkey attribute values and run again, so it can enroll its own.`);
        }
        if (await markCurrent(this.page, 'assert')) {
            try {
                await waitForReplacement(this.page, 15_000);
                return;
            } catch {
                // Fall through to the button
            }
        }
        if ((await detect(this.page)) !== 'mfa') {
            return;
        }
        await markCurrent(this.page);
        await this.page.click('#pk_button');
        try {
            await waitForReplacement(this.page);
        } catch {
            throw new Error(`The passkey wasn't accepted: ${await this.message()}`);
        }
    }

    /** The codes on the codes page; they're kept in memory only. */
    async readCodes(): Promise<string[]> {
        const codes = (await this.page.locator('#pk_code_list div').allInnerTexts()).map(code => code.trim()).filter(Boolean);
        seenSecrets.push(...codes);
        return codes;
    }

    /** The token on the helpdesk page after issuing one. */
    async readIssuedToken(): Promise<string> {
        const token = (await this.page.locator('#pk_form div[style*="monospace"]').innerText()).trim();
        seenSecrets.push(token);
        return token;
    }

    /** Removes passkeys the tests created, from the manage page, so they don't build up. */
    async removePasskeysNamed(prefix: string): Promise<void> {
        for (let i = 0; i < 10; i++) {
            const link = this.page.locator(`.pk-remove[data-name^="${prefix}"]`).first();
            if ((await link.count()) === 0) {
                return;
            }
            await this.act(() => link.click());
            await this.driveTo(['manage']);
        }
        throw new Error(`Couldn't remove the passkeys named ${prefix}*`);
    }

    /** Signs a new account up for its own software passkey through the manage contract. */
    static async enroll(browser: Browser, account: Account, contract: string): Promise<void> {
        if (loadPasskey(account.id)) {
            return;
        }
        const session = await Session.open(browser, account, contract);
        try {
            await session.driveTo(['manage']);
            if ((await session.page.locator('.pk-manage-table').count()) > 0) {
                throw new Error(`${account.id} already has passkeys, but none this script holds. `
                    + `Clear the account's passkey attribute values and run again.`);
            }
            await session.click('#pk_add');
            await session.driveTo(['manage'], { passkeyName: 'e2e' });
            const created = await session.authenticator.credentials();
            if (created.length !== 1) {
                throw new Error(`Expected one software passkey after enrolling, found ${created.length}`);
            }
            savePasskey(account.id, created[0]);
            await session.click('#pk_done');
        } finally {
            await session.context.close();
        }
    }
}

async function detect(page: Page): Promise<Kind | undefined> {
    try {
        return await page.evaluate((errors: string[]): Kind | undefined => {
            const find = (selector: string) => document.querySelector(selector);
            if (find('#Ecom_User_ID')) return 'password';
            // Before the others: its form also says "assert", and it has a Continue button
            if (find('#pk_userid') || find('#pk_reset')) return 'login';
            if (find('#pk_code_list')) return 'codes';
            if (find('.pk-gate-field')) return 'gate';
            if (find('#pk_code')) return 'recovery';
            if (find('#pk_issue') || find('#pk_another')) return 'helpdesk';
            if (find('.pk-manage')) return 'manage';
            if (find('#pk_continue')) return 'saved';
            const action = (find('#pk_form input[name=pk_action]') as HTMLInputElement | null)?.value;
            if (action === 'register') return 'register';
            if (action === 'assert') return 'mfa';
            const text = document.body?.innerText ?? '';
            if (!find('#pk_form') && errors.some(error => text.includes(error))) return 'error';
            return undefined;
        }, errorTexts);
    } catch {
        return undefined; // the page was navigating
    }
}

/** Tags the current form so its replacement can be seen; only an MFA form, if asked, as it moves on by itself. */
async function markCurrent(page: Page, onlyAction?: string): Promise<boolean> {
    return page.evaluate((only?: string) => {
        let marked = false;
        document.querySelectorAll('#pk_form, #IDPLogin').forEach(form => {
            const action = (form.querySelector('input[name=pk_action]') as HTMLInputElement | null)?.value;
            if (!only || action === only) {
                form.setAttribute('data-e2e-old', '');
                marked = true;
            }
        });
        return marked;
    }, onlyAction);
}

async function waitForReplacement(page: Page, timeout = STEP_TIMEOUT): Promise<void> {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
        const gone = await page.evaluate(() => !document.querySelector('[data-e2e-old]')).catch(() => false);
        if (gone) {
            await page.waitForLoadState('domcontentloaded').catch(() => undefined);
            return;
        }
        await page.waitForTimeout(200);
    }
    const message = await page.locator('#pk_msg').innerText().catch(() => '');
    throw new Error(`The page didn't move on within ${timeout / 1000}s${message ? `: ${message}` : ''}`);
}
