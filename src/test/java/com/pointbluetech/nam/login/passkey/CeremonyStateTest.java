package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class CeremonyStateTest {

    private static final Instant T0 = Instant.parse("2026-11-04T12:00:00Z");
    private static final String JSON = "{\"a\":\"x|y\"}";

    private final Map<String, Object> map = new HashMap<>();
    private final CeremonyState.Session session = new CeremonyState.Session() {
        @Override
        public Object get(String key) {
            return map.get(key);
        }

        @Override
        public void put(String key, Object value) {
            map.put(key, value);
        }
    };

    private CeremonyState state(String guid, Instant now) {
        return new CeremonyState(session, "card", guid, 300, Clock.fixed(now, ZoneOffset.UTC));
    }

    @Test
    void requestIsSingleUse() {
        state("u1", T0).put(CeremonyState.Type.ASSERTION, JSON);

        assertEquals(Optional.of(JSON), state("u1", T0).take(CeremonyState.Type.ASSERTION));
        assertFalse(state("u1", T0).take(CeremonyState.Type.ASSERTION).isPresent());
    }

    @Test
    void requestExpires() {
        state("u1", T0).put(CeremonyState.Type.ASSERTION, JSON);

        assertEquals(Optional.of(JSON), state("u1", T0.plusSeconds(300)).take(CeremonyState.Type.ASSERTION));

        state("u1", T0).put(CeremonyState.Type.ASSERTION, JSON);
        assertFalse(state("u1", T0.plusSeconds(301)).take(CeremonyState.Type.ASSERTION).isPresent());
    }

    @Test
    void requestOnlyCountsForItsTypeAndUser() {
        state("u1", T0).put(CeremonyState.Type.REGISTRATION, JSON);
        assertFalse(state("u1", T0).take(CeremonyState.Type.ASSERTION).isPresent());

        state("u1", T0).put(CeremonyState.Type.ASSERTION, JSON);
        assertFalse(state("u2", T0).take(CeremonyState.Type.ASSERTION).isPresent());
        assertFalse(state("u1", T0).take(CeremonyState.Type.ASSERTION).isPresent(), "a mismatch burns it");
    }

    @Test
    void enrollingIsPerUserAndClearable() {
        state("u1", T0).setEnrolling(true);

        assertTrue(state("u1", T0).enrolling());
        assertFalse(state("u2", T0).enrolling());

        state("u1", T0).clear();
        assertFalse(state("u1", T0).enrolling());
    }

    @Test
    void verifiedIsPerUserAndAgesOutButSurvivesClear() {
        state("u1", T0).markVerified();

        assertTrue(state("u1", T0.plusSeconds(300)).verifiedWithin(300));
        assertFalse(state("u1", T0.plusSeconds(301)).verifiedWithin(300));
        assertFalse(state("u2", T0).verifiedWithin(300));

        state("u1", T0).clear();
        assertTrue(state("u1", T0).verifiedWithin(300));
    }

    @Test
    void aProofCanBeForgottenByAnyMethod() {
        state("u1", T0).markVerified();
        new CeremonyState(session, "helpdesk-card", "u1", 300, Clock.fixed(T0, ZoneOffset.UTC)).forgetVerified();

        assertFalse(state("u1", T0).verifiedWithin(300));
    }

    @Test
    void actionTokenIsStableAndChecked() {
        CeremonyState state = state("u1", T0);
        assertFalse(state.checkActionToken("anything"), "no token issued yet");

        String token = state.actionToken();
        assertEquals(token, state.actionToken());
        assertTrue(state.checkActionToken(token));
        assertFalse(state.checkActionToken(token + "x"));
        assertFalse(state.checkActionToken(null));

        state.clear();
        assertFalse(state.checkActionToken(token));
    }

    @Test
    void pendingActionIsKeptExactlyOnceEvenWithSeparatorsInTheName() {
        state("u1", T0).setPendingAction("rename", "AQID", "my|odd|name");

        String[] pending = state("u1", T0.plusSeconds(10)).takePendingAction().get();
        assertEquals("rename", pending[0]);
        assertEquals("AQID", pending[1]);
        assertEquals("my|odd|name", pending[2]);
        assertFalse(state("u1", T0).takePendingAction().isPresent());
    }

    @Test
    void pendingActionHandlesMissingFields() {
        state("u1", T0).setPendingAction("add", null, null);

        String[] pending = state("u1", T0).takePendingAction().get();
        assertEquals("add", pending[0]);
        assertEquals("", pending[1]);
        assertEquals("", pending[2]);
    }

    @Test
    void pendingActionExpiresAndIsPerUser() {
        state("u1", T0).setPendingAction("delete", "AQID", null);
        assertFalse(state("u1", T0.plusSeconds(301)).takePendingAction().isPresent());

        state("u1", T0).setPendingAction("delete", "AQID", null);
        assertFalse(state("u2", T0).takePendingAction().isPresent());

        state("u1", T0).setPendingAction("delete", "AQID", null);
        state("u1", T0).clear();
        assertFalse(state("u1", T0).takePendingAction().isPresent());
    }

    @Test
    void pendingMessageIsShownOnce() {
        state("u1", T0).setPendingMessage("error.verify");

        assertEquals(Optional.of("error.verify"), state("u1", T0).takePendingMessage());
        assertFalse(state("u1", T0).takePendingMessage().isPresent());
    }

    @Test
    void setupCodeWorksOnceAndOnlyBeforeItExpires() {
        CeremonyState state = state("guid-1", T0);
        assertEquals(1, state.issueGateCode("123456"));
        assertFalse(map.values().toString().contains("123456"), "only a hash is kept");

        assertFalse(state.checkGateCode("654321", 600_000));
        assertFalse(state("guid-1", T0.plusSeconds(601)).checkGateCode("123456", 600_000), "expired");
        assertFalse(state("guid-2", T0).checkGateCode("123456", 600_000), "another user's state");
        assertTrue(state.checkGateCode(" 123 456 ", 600_000));
        assertFalse(state.checkGateCode("123456", 600_000), "used up");
        assertEquals(1, state.gateCodeSends(), "the send count survives");
    }

    @Test
    void aNewCodeReplacesTheOldOneAndCountsSends() {
        CeremonyState state = state("guid-1", T0);
        state.issueGateCode("111111");
        assertEquals(2, state.issueGateCode("222222"));

        assertFalse(state.checkGateCode("111111", 600_000));
        assertTrue(state.checkGateCode("222222", 600_000));
    }

    @Test
    void passedGatesAreRememberedPerUserAndClearedWithTheLogin() {
        CeremonyState state = state("guid-1", T0);
        state.passGate("EMAIL");
        state.passGate("HELPDESK");

        assertTrue(state.gatePassed("EMAIL"));
        assertTrue(state.gatePassed("HELPDESK"));
        assertFalse(state("guid-2", T0).gatePassed("EMAIL"));

        state.clear();
        assertFalse(state.gatePassed("EMAIL"));
        assertEquals(0, state.gateCodeSends());
    }

    @Test
    void askedQuestionsStayTiedToTheStoredSet() {
        CeremonyState state = state("guid-1", T0);
        state.setGateQuestions("set-a", java.util.List.of(0, 3, 1));

        assertEquals(java.util.List.of(0, 3, 1), state.gateQuestions("set-a").get());
        assertFalse(state.gateQuestions("set-b").isPresent(), "a changed set forgets them");
        assertFalse(state("guid-2", T0).gateQuestions("set-a").isPresent());

        state.passGate("QUESTIONS");
        assertFalse(state.gateQuestions("set-a").isPresent(), "gone once passed");
    }

    @Test
    void remembersTheWaitingNmasLogin() {
        CeremonyState state = state("guid-1", T0);
        assertFalse(state.gateNmas().isPresent());
        state.setGateNmas("check-1");
        assertEquals("check-1", state.gateNmas().get());
        assertFalse(state("guid-2", T0).gateNmas().isPresent(), "another method's state doesn't see it");

        state.setGateNmas(null);
        assertFalse(state.gateNmas().isPresent());
        state.setGateNmas("check-2");
        state.passGate("QUESTIONS");
        assertFalse(state.gateNmas().isPresent(), "gone once passed");
    }
}
