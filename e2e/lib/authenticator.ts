import fs from 'node:fs';
import path from 'node:path';
import type { CDPSession, Page } from '@playwright/test';

/**
 * Chrome's virtual authenticator: a software passkey that answers WebAuthn calls like a platform
 * authenticator with user verification, without any prompt.
 */

export interface StoredCredential {
    credentialId: string;
    isResidentCredential: boolean;
    rpId?: string;
    privateKey: string;
    userHandle?: string;
    signCount: number;
}

const STATE_DIR = path.join(__dirname, '../.state');

function stateFile(accountId: string): string {
    return path.join(STATE_DIR, `${accountId.replace(/[^A-Za-z0-9._-]/g, '_')}.json`);
}

/** The test account's passkey, kept between runs; it holds a private key, so the folder is gitignored. */
export function loadPasskey(accountId: string): StoredCredential | undefined {
    const file = stateFile(accountId);
    return fs.existsSync(file) ? (JSON.parse(fs.readFileSync(file, 'utf8')) as StoredCredential) : undefined;
}

export function savePasskey(accountId: string, credential: StoredCredential): void {
    fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(stateFile(accountId), JSON.stringify(credential, null, 2), { mode: 0o600 });
}

export class Authenticator {
    private constructor(private readonly cdp: CDPSession, private readonly id: string) {}

    /** Chrome allows one internal authenticator per page; a second one has to be another transport. */
    static async attach(page: Page, transport: 'internal' | 'usb' = 'internal'): Promise<Authenticator> {
        const cdp = await page.context().newCDPSession(page);
        await cdp.send('WebAuthn.enable', { enableUI: false });
        const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
            options: {
                protocol: 'ctap2',
                transport,
                hasResidentKey: true,
                hasUserVerification: true,
                isUserVerified: true,
                automaticPresenceSimulation: true,
            },
        });
        return new Authenticator(cdp, authenticatorId);
    }

    async add(credential: StoredCredential): Promise<void> {
        await this.cdp.send('WebAuthn.addCredential', { authenticatorId: this.id, credential });
    }

    async credentials(): Promise<StoredCredential[]> {
        const { credentials } = await this.cdp.send('WebAuthn.getCredentials', { authenticatorId: this.id });
        return credentials;
    }

    async remove(credentialId: string): Promise<void> {
        await this.cdp.send('WebAuthn.removeCredential', { authenticatorId: this.id, credentialId });
    }

    /**
     * Waits for this authenticator to stop holding a credential, as Chrome does when a page tells it
     * the site no longer has one (the WebAuthn Signals API). False if it's still there at the deadline.
     */
    async waitUntilGone(credentialId: string, timeout = 10_000): Promise<boolean> {
        const deadline = Date.now() + timeout;
        while (Date.now() < deadline) {
            if (!(await this.credentials()).some(c => c.credentialId === credentialId)) {
                return true;
            }
            await new Promise(resolve => setTimeout(resolve, 250));
        }
        return false;
    }
}
