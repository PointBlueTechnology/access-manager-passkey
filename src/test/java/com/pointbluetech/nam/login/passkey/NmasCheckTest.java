package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The hand-over between a waiting NMAS login and the requests that show questions and answer them. */
class NmasCheckTest {

    private static final String USER = "cn=pktest,o=novell";
    private static final List<String> QUESTIONS = List.of("First pet?", "Street?");

    private final List<NmasCheck> started = new ArrayList<>();

    @AfterEach
    void forgetChecks() {
        started.forEach(check -> NmasCheck.forget(check.id));
    }

    /** A login that asks the questions and passes only if the answers are these. */
    private static NmasCheck.Login expecting(String... right) {
        return check -> {
            Optional<List<String>> answers = check.ask(QUESTIONS);
            if (!answers.isPresent()) {
                return NmasCheck.CANCELLED;
            }
            return answers.get().equals(List.of(right)) ? 0 : -1697;
        };
    }

    private NmasCheck start(NmasCheck.Login login, long answerTimeoutMs) {
        NmasCheck check = NmasCheck.start(USER, login, answerTimeoutMs).orElseThrow();
        started.add(check);
        return check;
    }

    @Test
    void handsQuestionsOutAndAnswersBack() throws Exception {
        NmasCheck check = start(expecting("Rex", "Elm"), 5_000);
        assertEquals(Optional.of(QUESTIONS), check.awaitQuestions(5_000));
        assertEquals(Optional.of(QUESTIONS), check.waitingQuestions());
        assertTrue(NmasCheck.find(check.id, USER).isPresent());

        assertTrue(check.answer(List.of("Rex", "Elm")));
        assertEquals(OptionalInt.of(0), check.awaitResult(5_000));
        assertFalse(check.waitingQuestions().isPresent());
        assertFalse(check.answer(List.of("again")), "answers are taken once");
    }

    @Test
    void wrongAnswersComeBackAsTheLoginsStatus() throws Exception {
        NmasCheck check = start(expecting("Rex", "Elm"), 5_000);
        check.awaitQuestions(5_000);
        check.answer(List.of("Rex", "Oak"));
        assertEquals(OptionalInt.of(-1697), check.awaitResult(5_000));
    }

    @Test
    void belongsOnlyToItsOwner() throws Exception {
        NmasCheck check = start(expecting("Rex", "Elm"), 5_000);
        assertFalse(NmasCheck.find(check.id, "cn=someone-else,o=novell").isPresent());
        assertFalse(NmasCheck.find("not-an-id", USER).isPresent());
        assertFalse(NmasCheck.find(null, USER).isPresent());
    }

    @Test
    void stopsWaitingForAnswersAfterTheTimeout() throws Exception {
        NmasCheck check = start(expecting("Rex", "Elm"), 200);
        check.awaitQuestions(5_000);
        assertEquals(OptionalInt.of(NmasCheck.CANCELLED), check.awaitResult(5_000));
        assertFalse(check.answer(List.of("Rex", "Elm")), "too late");
    }

    @Test
    void forgettingCancelsAWaitingLogin() throws Exception {
        NmasCheck check = start(expecting("Rex", "Elm"), 60_000);
        check.awaitQuestions(5_000);
        NmasCheck.forget(check.id);
        assertEquals(OptionalInt.of(NmasCheck.CANCELLED), check.awaitResult(5_000));
        assertFalse(NmasCheck.find(check.id, USER).isPresent());
    }

    @Test
    void aLoginThatEndsEarlyHasNoQuestions() throws Exception {
        NmasCheck refused = start(check -> -1664, 5_000);
        assertEquals(Optional.empty(), refused.awaitQuestions(5_000));
        assertEquals(OptionalInt.of(-1664), refused.awaitResult(0));
        assertFalse(refused.failure().isPresent());

        NmasCheck broken = start(check -> {
            throw new java.io.IOException("connection refused");
        }, 5_000);
        assertEquals(Optional.empty(), broken.awaitQuestions(5_000));
        assertEquals(OptionalInt.of(NmasCheck.TRANSPORT_FAILED), broken.awaitResult(0));
        assertTrue(broken.failure().orElse("").contains("connection refused"));
    }

    @Test
    void waitingForQuestionsCanTimeOut() throws Exception {
        NmasCheck slow = start(check -> {
            Thread.sleep(2_000);
            return 0;
        }, 5_000);
        assertEquals(Optional.empty(), slow.awaitQuestions(100));
        assertFalse(slow.done());
    }

    @Test
    void limitsHowManyWaitAtOnce() throws Exception {
        int room = NmasCheck.MAX_CHECKS - NmasCheck.count();
        for (int i = 0; i < room; i++) {
            start(expecting("x"), 60_000);
        }
        assertFalse(NmasCheck.start(USER, expecting("x"), 60_000).isPresent());
        NmasCheck.forget(started.remove(0).id);
        assertTrue(NmasCheck.start(USER, expecting("x"), 60_000).map(started::add).orElse(false));
    }
}
