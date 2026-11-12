package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class RecoveryStoreTest {

    private static final String ATTR = "carLicense";
    private static final byte[] PEPPER = new byte[32];
    private static final Instant T0 = Instant.parse("2026-11-04T12:00:00Z");

    private final InMemoryAttributes directory = new InMemoryAttributes();

    private RecoveryStore store(String guid, Instant now) {
        return new RecoveryStore(directory, ATTR, ATTR, "", PEPPER, guid, 3, Clock.fixed(now, ZoneOffset.UTC));
    }

    private RecoveryStore store() {
        return store("guid-1", T0);
    }

    private List<String> values() {
        return directory.values.getOrDefault(ATTR, new ArrayList<>());
    }

    @Test
    void codesHaveTheExpectedShapeAndAreOnlyStoredHashed() {
        List<String> codes = store().generateCodes(10);

        assertEquals(10, codes.size());
        assertEquals(10, values().size());
        for (String code : codes) {
            assertTrue(code.matches("[A-Z2-7]{4}(-[A-Z2-7]{4}){3}"), code);
            assertFalse(String.join("|", values()).contains(code.replace("-", "")));
        }
        assertEquals(10, store().codesLeft());
    }

    @Test
    void eachCodeWorksExactlyOnce() {
        String code = store().generateCodes(2).get(0);

        assertEquals(RecoveryStore.Match.CODE, store().consume(code));
        assertEquals(RecoveryStore.Match.NONE, store().consume(code));
        assertEquals(1, store().codesLeft());
    }

    @Test
    void codesForgiveCaseSpacesAndDashes() {
        String code = store().generateCodes(1).get(0);

        assertEquals(RecoveryStore.Match.CODE, store().consume("  " + code.toLowerCase().replace("-", " ") + " "));
    }

    @Test
    void regeneratingInvalidatesTheOldSet() {
        String old = store().generateCodes(3).get(0);
        store().generateCodes(3);

        assertEquals(RecoveryStore.Match.NONE, store().consume(old));
        assertEquals(3, store().codesLeft());
    }

    @Test
    void anotherUsersCodeDoesNotWork() {
        String code = store("guid-1", T0).generateCodes(1).get(0);

        assertEquals(RecoveryStore.Match.NONE, store("guid-2", T0).consume(code));
    }

    @Test
    void differentPepperDoesNotWork() {
        String code = store().generateCodes(1).get(0);
        byte[] other = new byte[32];
        Arrays.fill(other, (byte) 1);

        assertEquals(RecoveryStore.Match.NONE,
                new RecoveryStore(directory, ATTR, ATTR, "", other, "guid-1", 3, Clock.fixed(T0, ZoneOffset.UTC)).consume(code));
    }

    @Test
    void blankAndOversizedInputIsRejectedWithoutCountingAgainstAToken() {
        RecoveryStore.IssuedToken token = store().issueToken(3600);

        assertEquals(RecoveryStore.Match.NONE, store().consume(null));
        assertEquals(RecoveryStore.Match.NONE, store().consume(" - "));
        assertEquals(RecoveryStore.Match.NONE, store().consume("A".repeat(65)));
        assertTrue(values().get(0).endsWith(":0"));
        assertEquals(RecoveryStore.Match.TOKEN, store().consume(token.display));
    }

    @Test
    void tokenWorksOnceAndIsHashed() {
        RecoveryStore.IssuedToken token = store().issueToken(3600);

        assertTrue(token.display.matches("[A-Z2-7]{4}(-[A-Z2-7]{4}){3}"), token.display);
        assertFalse(values().get(0).contains(token.display.replace("-", "")));
        assertEquals(T0.plusSeconds(3600), token.expires);
        assertEquals(RecoveryStore.Match.TOKEN, store().consume(token.display));
        assertEquals(RecoveryStore.Match.NONE, store().consume(token.display));
        assertTrue(values().isEmpty());
    }

    @Test
    void newTokenReplacesTheOldOne() {
        RecoveryStore.IssuedToken first = store().issueToken(3600);
        RecoveryStore.IssuedToken second = store().issueToken(3600);

        assertNotEquals(first.display, second.display);
        assertEquals(1, values().size());
        assertEquals(RecoveryStore.Match.TOKEN, store().consume(second.display));
    }

    @Test
    void expiredTokenFailsAndIsRemoved() {
        RecoveryStore.IssuedToken token = store().issueToken(3600);

        assertEquals(RecoveryStore.Match.NONE, store("guid-1", T0.plusSeconds(3601)).consume(token.display));
        assertTrue(values().isEmpty());
    }

    @Test
    void tooManyWrongEntriesRemoveTheToken() {
        RecoveryStore.IssuedToken token = store().issueToken(3600);

        store().consume("WRONG-WRONG");
        store().consume("WRONG-WRONG");
        assertEquals(1, values().size());
        store().consume("WRONG-WRONG");

        assertTrue(values().isEmpty());
        assertEquals(RecoveryStore.Match.NONE, store().consume(token.display));
    }

    @Test
    void passkeysSharingTheAttributeSurviveEverything() {
        String passkey = "v1:{\"id\":\"AQID\",\"pk\":\"BAUG\",\"sc\":5,\"uh\":\"BwgJ\",\"nm\":\"Laptop\","
                + "\"aa\":\"00\",\"tr\":[],\"be\":true,\"bs\":false,\"cr\":\"2026-11-01T14:03:00Z\"}";
        directory.values.put(ATTR, new ArrayList<>(List.of(passkey, "SOMEPLATE")));

        String code = store().generateCodes(2).get(0);
        store().consume(code);
        RecoveryStore.IssuedToken token = store().issueToken(3600);
        store().consume("WRONG");
        store().consume(token.display);
        store().markRecovered();

        assertTrue(values().contains(passkey));
        assertTrue(values().contains("SOMEPLATE"));

        PasskeyStore passkeys = new PasskeyStore(directory, ATTR, "");
        assertEquals(1, passkeys.load().size());
        passkeys.update(records -> records);
        assertEquals(1, store().codesLeft(), "passkey writes keep the codes");
        assertTrue(store().recoveredAt().isPresent(), "passkey writes keep the recovery time");
    }

    @Test
    void noCooldownWithoutARecoveryOrWhenTurnedOff() {
        assertFalse(store().recoveredAt().isPresent());
        assertFalse(store().codesBlockedUntil(3600).isPresent());

        store().markRecovered();
        assertFalse(store().codesBlockedUntil(0).isPresent(), "a cool-down of 0 is off");
    }

    @Test
    void recoveryHoldsBackNewCodesForTheCooldown() {
        store().markRecovered();

        assertEquals(T0, store().recoveredAt().get());
        assertEquals(T0.plusSeconds(3600), store("guid-1", T0.plusSeconds(3599)).codesBlockedUntil(3600).get());
        assertFalse(store("guid-1", T0.plusSeconds(3600)).codesBlockedUntil(3600).isPresent());
    }

    @Test
    void aLaterRecoveryRestartsTheCooldownAndKeepsOneValue() {
        store().markRecovered();
        store("guid-1", T0.plusSeconds(1800)).markRecovered();

        assertEquals(T0.plusSeconds(1800), store().recoveredAt().get());
        assertEquals(1, values().stream().filter(v -> v.startsWith(RecoveryStore.RECOVERED_PREFIX)).count());
        assertTrue(store("guid-1", T0.plusSeconds(3700)).codesBlockedUntil(3600).isPresent());
    }

    @Test
    void recoveryTimeSurvivesCodesAndIsntACode() {
        store().generateCodes(3);
        store().markRecovered();
        store().generateCodes(3);

        assertEquals(3, store().codesLeft());
        assertEquals(T0, store().recoveredAt().get());
        assertTrue(RecoveryStore.isRecoveryValue(RecoveryStore.RECOVERED_PREFIX + "1"));
        assertFalse(RecoveryStore.isRecoveryValue("v1:{}"));
    }

    @Test
    void failedDirectoryReadIsNotTreatedAsAWrongCode() {
        directory.readsFail = true;

        assertThrows(PasskeyStoreException.class, () -> store().consume("AAAA-BBBB"));
    }

    @Test
    void helpdeskGroupMatchIgnoresCaseAndSpacing() {
        List<String> memberships = List.of("cn=staff,o=novell", "CN=HelpDesk, O=Novell");

        assertTrue(PasskeyConfig.isMemberOf(memberships, "cn=helpdesk,o=novell"));
        assertFalse(PasskeyConfig.isMemberOf(memberships, "cn=helpdesk2,o=novell"));
        assertFalse(PasskeyConfig.isMemberOf(List.of(), "cn=helpdesk,o=novell"));
        assertFalse(PasskeyConfig.isMemberOf(memberships, ""));
    }

    @Test
    void theEnrollmentGateTakesOnlyAHelpdeskToken() {
        String code = store().generateCodes(1).get(0);
        assertFalse(store().consumeToken(code), "a recovery code isn't a helpdesk code");
        assertEquals(1, store().codesLeft());

        RecoveryStore.IssuedToken token = store().issueToken(3600);
        assertTrue(store().consumeToken(token.display));
        assertFalse(store().consumeToken(token.display), "used up");
    }
}
