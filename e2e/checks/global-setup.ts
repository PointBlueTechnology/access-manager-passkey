import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

/**
 * Sets up the Admin Console for the E2E_CHECK group with amcli (access-manager-cli), then puts it
 * back afterwards. checks/setup/<group>.json holds what the group needs; a group without one (such
 * as prepare) needs nothing. amcli's backup of the settings it changed is kept in .state until
 * the teardown has applied it, so a run that was cut short is put right at the start of the next.
 *
 * Needs AMCLI_URL, AMCLI_PASSWORD and the other AMCLI_ settings in .env (see .env.example).
 * Set E2E_CHECK_SETUP=manual to set the console up by hand instead.
 */
const STATE = path.join(__dirname, '../.state');
const RESTORE = path.join(STATE, 'check-setup-restore.json');

function cliPath(): string {
    if (process.env.AMCLI_BIN) {
        return process.env.AMCLI_BIN;
    }
    const require = createRequire(__filename);
    try {
        return path.join(path.dirname(require.resolve('access-manager-cli/package.json')), 'dist/cli.js');
    } catch {
        throw new Error('amcli (access-manager-cli) isn\'t installed: run npm install in e2e, or set AMCLI_BIN to its cli.js, '
            + 'or set E2E_CHECK_SETUP=manual to set the Admin Console up by hand');
    }
}

function amcli(...args: string[]): Record<string, unknown> {
    const result = spawnSync(process.execPath, [cliPath(), ...args, '--compact', '--quiet'], { encoding: 'utf8', env: process.env });
    if (result.status !== 0) {
        throw new Error(`amcli ${args.join(' ')} failed:\n${result.stderr || result.stdout}`);
    }
    return JSON.parse(result.stdout || 'null');
}

function summary(applied: unknown): string {
    return ((applied as { action: string; kind: string; name: string }[] | undefined) ?? [])
        .filter(item => item.action !== 'unchanged' && item.action !== 'absent')
        .map(item => `${item.action} ${item.kind} ${item.name}`)
        .join(', ') || 'nothing to change';
}

function restore(reason: string): void {
    console.log(`[checks] ${reason}: putting the Admin Console back`);
    const result = amcli('apply', '-f', RESTORE, '--yes');
    console.log(`[checks] restored: ${summary(result.applied)}`);
    amcli('update', '--yes', '--wait');
    fs.rmSync(RESTORE);
}

export default async function globalSetup(): Promise<(() => Promise<void>) | undefined> {
    const check = process.env.E2E_CHECK ?? '';
    const setup = path.join(__dirname, 'setup', `${check}.json`);
    if (process.env.E2E_CHECK_SETUP === 'manual') {
        console.log('[checks] E2E_CHECK_SETUP=manual: using the Admin Console as it is');
        return undefined;
    }
    if (fs.existsSync(RESTORE)) {
        restore('An earlier run didn\'t finish');
    }
    if (!check || !fs.existsSync(setup)) {
        return undefined;
    }
    fs.mkdirSync(STATE, { recursive: true, mode: 0o700 });
    try {
        const result = amcli('apply', '-f', setup, '--backup', RESTORE);
        console.log(`[checks] set up ${check}: ${summary(result.applied)}`);
        amcli('update', '--yes', '--wait');
    } catch (error) {
        if (fs.existsSync(RESTORE)) {
            restore('Setting up failed');
        }
        throw error;
    }
    return async () => restore(`${check} finished`);
}
