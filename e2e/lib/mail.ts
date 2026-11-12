/**
 * Reads the emails NAM sent, from MailCatcher's HTTP API. Optional: the checks run only when
 * E2E_USER_MAIL is set to the test user's mail value and NOTIFY_EMAIL is on in NAM.
 */

interface CaughtMessage {
    id: number;
    recipients: string[];
    subject: string;
}

function mailcatcher(): string {
    return (process.env.E2E_MAILCATCHER_URL ?? 'http://localhost:1080').replace(/\/$/, '');
}

/** Read when called, not on import: a test file can load before e2e/.env has been read. */
export function userMail(): string | undefined {
    return process.env.E2E_USER_MAIL?.trim() || undefined;
}

async function messages(): Promise<CaughtMessage[]> {
    const response = await fetch(`${mailcatcher()}/messages`);
    if (!response.ok) {
        throw new Error(`MailCatcher at ${mailcatcher()} answered ${response.status}`);
    }
    return (await response.json()) as CaughtMessage[];
}

/** The newest message ID now; pass it to the other calls to look only at mail sent after it. */
export async function mailMark(): Promise<number> {
    if (!userMail()) {
        return 0;
    }
    return Math.max(0, ...(await messages()).map(message => message.id));
}

function isTo(message: CaughtMessage, address: string): boolean {
    return message.recipients.some(recipient => recipient.replace(/[<>]/g, '').trim().toLowerCase() === address.toLowerCase());
}

/** Waits for a message to the address with each subject; the notification thread sends a moment later. */
export async function expectMail(mark: number, address: string, ...subjects: string[]): Promise<void> {
    const deadline = Date.now() + 20_000;
    while (true) {
        const sent = (await messages()).filter(message => message.id > mark && isTo(message, address));
        const missing = subjects.filter(subject => !sent.some(message => message.subject === subject));
        if (missing.length === 0) {
            return;
        }
        if (Date.now() > deadline) {
            throw new Error(`No email to ${address} with subject ${missing.map(s => `"${s}"`).join(', ')}. `
                + `Got: ${sent.map(message => `"${message.subject}"`).join(', ') || 'nothing'}`);
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
}

/** How many messages since the mark contain any of the values, in either part; only the count comes back. */
export async function countValuesInMail(mark: number, values: string[]): Promise<number> {
    const variants = [...new Set(values.flatMap(value => [value, value.replace(/-/g, '')]))].map(v => v.toLowerCase());
    let count = 0;
    for (const message of (await messages()).filter(m => m.id > mark)) {
        const parts = await Promise.all(['plain', 'html'].map(async kind => {
            const response = await fetch(`${mailcatcher()}/messages/${message.id}.${kind}`);
            return response.ok ? (await response.text()).toLowerCase() : '';
        }));
        if (variants.some(value => parts.some(part => part.includes(value)))) {
            count++;
        }
    }
    return count;
}

/** The plain text of the newest message to the address with the subject, waiting for it to arrive. */
export async function readMail(mark: number, address: string, subject: string): Promise<string> {
    await expectMail(mark, address, subject);
    const found = (await messages())
        .filter(message => message.id > mark && isTo(message, address) && message.subject === subject)
        .sort((a, b) => b.id - a.id)[0];
    const response = await fetch(`${mailcatcher()}/messages/${found.id}.plain`);
    return response.text();
}
