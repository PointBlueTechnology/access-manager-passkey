import { execFileSync } from 'node:child_process';
import { env } from './env';

/** Reads the Identity Server log over ssh, from a byte offset taken before each step. */

const SSH = ['-o', 'LogLevel=ERROR', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10'];

function quote(text: string): string {
    return `'${text.replace(/'/g, `'\\''`)}'`;
}

function remote(command: string, input?: string): string {
    return execFileSync('ssh', [...SSH, env.ssh, command], {
        input,
        maxBuffer: 256 * 1024 * 1024,
        stdio: ['pipe', 'pipe', 'pipe'],
    }).toString();
}

/** Where the log ends now; pass it to the other calls to look only at what's written after. */
export function logMark(): number {
    const size = Number(remote(`stat -c %s ${quote(env.log)}`).trim());
    if (!Number.isFinite(size)) {
        throw new Error(`Couldn't read the size of ${env.log} on ${env.ssh}`);
    }
    return size;
}

/** The passkey class's lines and NAM's sign-in and method-result lines since the mark. */
export function passkeyLines(mark: number): string[] {
    return remote(`tail -c +${mark + 1} ${quote(env.log)} | grep -E '\\[Passkey|Authenticated user|Authentication method .* (succeeded|failed)|Password Fetch Class' || true`)
        .split('\n')
        .filter(Boolean);
}

/** Waits for a line matching each pattern; the log is written a moment after the page answers. */
export async function expectLog(mark: number, ...patterns: RegExp[]): Promise<void> {
    const deadline = Date.now() + 20_000;
    let missing = patterns;
    while (true) {
        const lines = passkeyLines(mark);
        missing = patterns.filter(pattern => !lines.some(line => pattern.test(line)));
        if (missing.length === 0) {
            return;
        }
        if (Date.now() > deadline) {
            const recent = lines.slice(-15).map(line => line.replace(/<\/?amLogEntry>/g, '').trim()).join('\n  ');
            throw new Error(`No log line matching ${missing.join(', ')}.\nPasskey lines since the step began:\n  ${recent}`);
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
}

export function expectNoLog(mark: number, pattern: RegExp): void {
    const found = passkeyLines(mark).filter(line => pattern.test(line));
    if (found.length > 0) {
        throw new Error(`Unexpected log line matching ${pattern}:\n  ${found.join('\n  ')}`);
    }
}

/**
 * How many log lines since the mark contain any of the values, with or without dashes. The values
 * go over ssh's stdin, so they never appear on a command line, and only the count comes back.
 */
export function countValuesInLog(mark: number, values: string[]): number {
    if (values.length === 0) {
        return 0;
    }
    const patterns = [...new Set(values.flatMap(value => [value, value.replace(/-/g, '')]))].join('\n') + '\n';
    const out = remote(`exec 3<&0; tail -c +${mark + 1} ${quote(env.log)} | grep -c -i -F -f /dev/fd/3 || true`, patterns);
    return Number(out.trim());
}
