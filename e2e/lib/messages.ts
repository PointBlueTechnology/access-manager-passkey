import fs from 'node:fs';
import path from 'node:path';

/** The texts the pages show, read from the class's own bundle so the tests follow any rewording. */
const BUNDLE = path.join(__dirname, '../../src/main/resources/com/pointbluetech/nam/login/passkey/PasskeyMessages.properties');

const messages = new Map<string, string>();
for (const line of fs.readFileSync(BUNDLE, 'utf8').split(/\r?\n/)) {
    const match = /^\s*([^#!\s][^=:]*?)\s*[=:]\s*(.*)$/.exec(line);
    if (match) {
        messages.set(match[1], match[2].trim());
    }
}

export function msg(key: string): string {
    const text = messages.get(key);
    if (text === undefined) {
        throw new Error(`No message ${key} in PasskeyMessages.properties`);
    }
    return text;
}

/** Every error text, for spotting NAM's error page. */
export const errorTexts = [...messages.entries()].filter(([key]) => key.startsWith('error.')).map(([, text]) => text);
