import { expect, test } from '@playwright/test';
import { env } from '../lib/env';
import { expectLog, expectNoLog, logMark } from '../lib/idpLog';
import { msg } from '../lib/messages';
import { Session } from '../lib/nam';

/**
 * ENROLL_GATES=questions with SSPR's stored answers. Needs a MANAGE contract with that set
 * (E2E_CONTRACT_QUESTIONS) and QUESTIONS_SSPR_ATTRIBUTE pointing where e2e/fixtures/sspr-responses.ldif
 * put the answers on the E2E_ENROLL_ID account. The passkey made here is removed again.
 *
 * The NMAS test needs a second contract with QUESTIONS_STORE=nmas (E2E_CONTRACT_QUESTIONS_NMAS), and
 * the same questions and answers set in NMAS for that account.
 */
test.describe.configure({ mode: 'serial' });

const NAME = 'e2e-questions';

/** The answers in e2e/fixtures/sspr-responses.ldif; test data, nothing real. */
const ANSWERS: Record<string, string> = {
    'E2E required question one?': 'Blue Kestrel',
    'E2E required question two?': 'Seven Oaks',
    'E2E random question one?': 'Copper Kettle',
    'E2E random question two?': 'Paper Lantern',
};

function re(text: string): RegExp {
    return new RegExp(text);
}

async function askedQuestions(session: Session): Promise<string[]> {
    return (await session.page.locator('label[for^="pk_answer"]').allInnerTexts()).map(text => text.trim());
}

async function answer(session: Session, questions: string[], wrongIndex?: number) {
    for (let i = 0; i < questions.length; i++) {
        const right = ANSWERS[questions[i]];
        expect(right, `an answer for "${questions[i]}"`).toBeTruthy();
        // Different case and spacing, as a user might type it
        await session.page.fill(`#pk_answer${i}`, i === wrongIndex ? 'not the answer' : `  ${right.toLowerCase()} `);
    }
    return session.click('#pk_button');
}

test('a first passkey needs the right answers to the SSPR security questions', async ({ browser }) => {
    const account = env.enroll();
    test.skip(!env.contracts.questions || !account,
        'set E2E_CONTRACT_QUESTIONS, E2E_ENROLL_ID and E2E_ENROLL_PASSWORD, and load e2e/fixtures/sspr-responses.ldif');
    const mark = logMark();
    const session = await Session.open(browser, account!, env.contracts.questions!);
    try {
        expect(await session.driveTo(['gate'])).toBe('gate');
        expect(await session.text()).toContain(msg('gate.questionsIntro'));
        const questions = await askedQuestions(session);
        // Both required questions and one of the two random ones
        expect(questions).toHaveLength(3);
        expect(questions).toEqual(expect.arrayContaining(['E2E required question one?', 'E2E required question two?']));

        expect(await answer(session, questions, 2)).toBe('gate');
        expect(await session.message()).toBe(msg('error.questionsWrong'));
        expect(await askedQuestions(session), 'the same questions again').toEqual(questions);

        expect(await answer(session, questions)).toBe('register');
        expect(await session.driveTo(['manage'], { passkeyName: NAME })).toBe('manage');
        await session.removePasskeysNamed(NAME);
        await expect(session.page.locator('.pk-manage-table')).toHaveCount(0);

        await expectLog(mark,
            re(`Wrong security answers for ${account!.logPattern} \\(1 of ${env.maxFailed}\\)`),
            re(`First-passkey check QUESTIONS passed for ${account!.logPattern}`),
            re(`Registered passkey '${NAME}`));
        expectNoLog(mark, /Blue Kestrel|Seven Oaks|Copper Kettle|Paper Lantern|not the answer/i);
    } finally {
        await session.close();
    }
});

test('a first passkey needs the right answers to the NMAS security questions', async ({ browser }) => {
    const account = env.enroll();
    test.skip(!env.contracts.questionsNmas || !account,
        'set E2E_CONTRACT_QUESTIONS_NMAS, E2E_ENROLL_ID and E2E_ENROLL_PASSWORD, and set the same answers in NMAS');
    const mark = logMark();
    const session = await Session.open(browser, account!, env.contracts.questionsNmas!);
    try {
        expect(await session.driveTo(['gate'])).toBe('gate');
        expect(await session.text()).toContain(msg('gate.questionsIntro'));
        // eDirectory picks the questions, and picks again after a wrong answer
        const questions = await askedQuestions(session);
        expect(questions.length).toBeGreaterThan(0);

        expect(await answer(session, questions, questions.length - 1)).toBe('gate');
        expect(await session.message()).toBe(msg('error.questionsWrong'));

        expect(await answer(session, await askedQuestions(session))).toBe('register');
        expect(await session.driveTo(['manage'], { passkeyName: NAME })).toBe('manage');
        await session.removePasskeysNamed(NAME);
        await expect(session.page.locator('.pk-manage-table')).toHaveCount(0);

        await expectLog(mark,
            re(`eDirectory refused the security answers for ${account!.logPattern}`),
            re(`Wrong security answers for ${account!.logPattern} \\(1 of ${env.maxFailed}\\)`),
            re(`First-passkey check QUESTIONS passed for ${account!.logPattern}`),
            re(`Registered passkey '${NAME}`));
        expectNoLog(mark, /Blue Kestrel|Seven Oaks|Copper Kettle|Paper Lantern|not the answer/i);
    } finally {
        await session.close();
    }
});
