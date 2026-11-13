/**
 * Sets up the browser tests' accounts in a test eDirectory, from fixtures/test-accounts.ldif and
 * fixtures/sspr-responses.ldif, with the IDs, mail values and passwords in e2e/.env.
 *
 *   npm run accounts -- load      create the accounts and group (again: existing entries are kept),
 *                                 set every password from .env, add the SSPR answers
 *   npm run accounts -- disable   disable E2E_DISABLED_ID, once the tests have given it a passkey
 *   npm run accounts -- enable    enable it again
 *   npm run accounts -- print     show the LDIF that load sends, with the passwords left out
 *
 * Runs ldapmodify as E2E_LDAP_ADMIN_DN, with E2E_LDAP_ADMIN_PASSWORD if it's set, or else it asks on
 * the terminal. Passwords reach it on pipes only: never on its command line, on disk or on screen. macOS's own ldapmodify ignores
 * LDAPTLS_CACERT, so the Homebrew OpenLDAP one is used when it's installed.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const root = path.join(import.meta.dirname, '..');
const envFile = path.join(root, '.env');
if (fs.existsSync(envFile)) {
    process.loadEnvFile(envFile);
}

function setting(name: string, fallback?: string): string {
    const value = process.env[name]?.trim() || fallback;
    if (!value) {
        throw new Error(`Set ${name} in e2e/.env (see e2e/.env.example)`);
    }
    return value;
}

const users = setting('E2E_LDAP_USERS');
const groups = setting('E2E_LDAP_GROUPS', users);
const ids = {
    AGENT_ID: setting('E2E_AGENT_ID'),
    USER_ID: setting('E2E_USER_ID'),
    DISABLED_ID: setting('E2E_DISABLED_ID', 'disabledTest'),
    ENROLL_ID: setting('E2E_ENROLL_ID', 'pktest-enroll'),
};
const values: Record<string, string> = {
    ...ids,
    USERS: users,
    GROUPS: groups,
    USER_MAIL: setting('E2E_USER_MAIL', `${ids.USER_ID}@namapp1.test`),
    ENROLL_MAIL: setting('E2E_ENROLL_MAIL', `${ids.ENROLL_ID}@namapp1.test`),
};

function dn(id: string): string {
    return `cn=${id},${users}`;
}

function fill(template: string): string {
    return template.replace(/@([A-Z_]+)@/g, (match, name: string) => {
        const value = values[name];
        if (value === undefined) {
            throw new Error(`No value for ${match}`);
        }
        return value;
    });
}

function accounts(): string {
    return fill(fs.readFileSync(path.join(root, 'fixtures/test-accounts.ldif'), 'utf8'));
}

/** The SSPR answers, on the enroll account and in the attribute QUESTIONS_SSPR_ATTRIBUTE names. */
function answers(): string {
    const attribute = setting('E2E_SSPR_ATTRIBUTE', 'carLicense');
    return fs
        .readFileSync(path.join(root, 'fixtures/sspr-responses.ldif'), 'utf8')
        .replace(/^dn: .*$/m, `dn: ${dn(ids.ENROLL_ID)}`)
        .replace(/^add: carLicense$/m, `add: ${attribute}`)
        .replace(/^carLicense:/m, `${attribute}:`);
}

function passwords(): string {
    const accounts: [string, string | undefined][] = [
        [ids.AGENT_ID, process.env.E2E_AGENT_PASSWORD],
        [ids.USER_ID, process.env.E2E_USER_PASSWORD],
        [ids.DISABLED_ID, process.env.E2E_DISABLED_PASSWORD],
        [ids.ENROLL_ID, process.env.E2E_ENROLL_PASSWORD],
    ];
    return accounts
        .filter(([, password]) => password)
        .map(([id, password]) =>
            `dn: ${dn(id)}\nchangetype: modify\nreplace: userPassword\nuserPassword:: ${Buffer.from(password!, 'utf8').toString('base64')}\n`)
        .join('\n');
}

function loginDisabled(disabled: boolean): string {
    return `dn: ${dn(ids.DISABLED_ID)}\nchangetype: modify\nreplace: loginDisabled\nloginDisabled: ${disabled ? 'TRUE' : 'FALSE'}\n`;
}

async function ldapmodify(ldif: string): Promise<number> {
    const brew = '/opt/homebrew/opt/openldap/bin/ldapmodify';
    const command = process.env.E2E_LDAPMODIFY?.trim() || (fs.existsSync(brew) ? brew : 'ldapmodify');
    const env = { ...process.env };
    const ca = process.env.E2E_LDAP_CACERT?.trim();
    if (ca) {
        env.LDAPTLS_CACERT = path.resolve(root, ca);
    }
    const password = process.env.E2E_LDAP_ADMIN_PASSWORD;
    // -c: carry on past entries that already exist, so load can be run again.
    // -y /dev/fd/3: the admin password, from a pipe of its own
    const args = ['-x', '-c', '-H', setting('E2E_LDAP_URL'), '-D', setting('E2E_LDAP_ADMIN_DN'), ...(password ? ['-y', '/dev/fd/3'] : ['-W'])];
    const child = spawn(command, args, { stdio: ['pipe', 'inherit', 'inherit', 'pipe'], env });
    const done = new Promise<number>((resolve, reject) => {
        child.on('error', reject);
        child.on('close', code => resolve(code ?? 1));
    });
    const secret = child.stdio[3] as NodeJS.WritableStream;
    secret.end(password ?? '');
    child.stdin!.end(ldif);
    return done;
}

const action = process.argv[2];
switch (action) {
    case 'load':
        process.exitCode = await ldapmodify(`${accounts()}\n${passwords()}\n${answers()}`);
        break;
    case 'disable':
    case 'enable':
        process.exitCode = await ldapmodify(loginDisabled(action === 'disable'));
        break;
    case 'print':
        console.log(`${accounts()}\n${answers()}`);
        break;
    default:
        console.error('Usage: npm run accounts -- load | disable | enable | print');
        process.exitCode = 2;
}
