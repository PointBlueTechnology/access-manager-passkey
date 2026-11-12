import fs from 'node:fs';
import path from 'node:path';

// Also read here, not only in playwright.config.ts, so settings are there whatever loads first
const envFile = path.join(__dirname, '../.env');
if (fs.existsSync(envFile)) {
    process.loadEnvFile(envFile);
}

export interface Account {
    id: string;
    password: string;
    /** Matches the account's DN in the IDP log */
    logPattern: string;
}

function setting(name: string, fallback: string): string {
    const value = process.env[name]?.trim();
    return value ? value : fallback;
}

function required(name: string): string {
    const value = process.env[name]?.trim();
    if (!value) {
        throw new Error(`Set ${name} in e2e/.env (see e2e/.env.example)`);
    }
    return value;
}

function escapeRegex(text: string): string {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function account(kind: 'AGENT' | 'USER' | 'DISABLED' | 'ENROLL'): Account {
    const id = required(`E2E_${kind}_ID`);
    const dn = process.env[`E2E_${kind}_DN`]?.trim();
    return {
        id,
        // The disabled account only needs one to enroll, while it's briefly enabled
        password: kind === 'DISABLED' ? (process.env.E2E_DISABLED_PASSWORD ?? '') : required(`E2E_${kind}_PASSWORD`),
        logPattern: dn ? escapeRegex(dn) : `cn=${escapeRegex(id)},[^ ]*`,
    };
}

export const env = {
    baseUrl: setting('E2E_BASE_URL', 'https://namapp1.pointbluetech.com'),
    ssh: setting('E2E_SSH', 'root@192.168.201.90'),
    log: setting('E2E_LOG', '/opt/novell/nam/idp/logs/catalina.out'),
    contracts: {
        manage: setting('E2E_CONTRACT_MANAGE', 'PasskeyManage'),
        recovery: setting('E2E_CONTRACT_RECOVERY', 'PasskeyRecovery'),
        helpdesk: setting('E2E_CONTRACT_HELPDESK', 'PasskeyHeldesk'),
        login: setting('E2E_CONTRACT_LOGIN', 'PasskeyLogin'),
        /** Optional: a LOGIN contract whose method has PASSKEY_ONLY=true; its test is skipped without it */
        passkeyOnly: process.env.E2E_CONTRACT_PASSKEY_ONLY?.trim() || undefined,
        /** Optional: a MANAGE contract whose method has ENROLL_GATES=email; its test is skipped without it */
        gated: process.env.E2E_CONTRACT_GATED?.trim() || undefined,
        /** Optional: a MANAGE contract whose method has ENROLL_GATES=questions; its test is skipped without it */
        questions: process.env.E2E_CONTRACT_QUESTIONS?.trim() || undefined,
        /** Optional: the same check with QUESTIONS_STORE=nmas; its test is skipped without it */
        questionsNmas: process.env.E2E_CONTRACT_QUESTIONS_NMAS?.trim() || undefined,
    },
    maxFailed: Number(setting('E2E_MAX_FAILED', '5')),
    /** RECOVERY_COOLDOWN_SEC as set in NAM; 0 skips the cool-down checks. The tests wait it out, so keep it short. */
    recoveryCooldownSec: Number(setting('E2E_RECOVERY_COOLDOWN_SEC', '0')),
    agent: () => account('AGENT'),
    user: () => account('USER'),
    /** Optional: a disabled account, whose tests are skipped when it isn't set */
    disabled: (): Account | undefined => (process.env.E2E_DISABLED_ID?.trim() ? account('DISABLED') : undefined),
    /** Optional: an account with no passkey, for the first-passkey checks; it's left with none again */
    enroll: (): Account | undefined => (process.env.E2E_ENROLL_ID?.trim() ? account('ENROLL') : undefined),
    enrollMail: (): string | undefined => process.env.E2E_ENROLL_MAIL?.trim() || undefined,
};
