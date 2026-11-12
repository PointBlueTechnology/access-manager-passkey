package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AccountRestrictionsTest {

    private static final Instant NOW = Instant.parse("2026-11-10T16:17:10Z");

    private final InMemoryAttributes directory = new InMemoryAttributes();
    /** Attributes the proxy account isn't allowed to read; eDirectory leaves them out of a read. */
    private final Set<String> hidden = new HashSet<>();
    private boolean rightsUnknown;

    private boolean canRead(String attribute) {
        if (rightsUnknown) {
            throw new PasskeyStoreException("Get Effective Privileges failed");
        }
        return !hidden.contains(attribute);
    }

    private void set(String attribute, String value) {
        directory.values.put(attribute, new ArrayList<>(List.of(value)));
    }

    private Optional<String> refusal() {
        // As eDirectory does: an attribute the proxy can't read comes back with no values
        for (String attribute : hidden) {
            directory.values.remove(attribute);
        }
        return AccountRestrictions.refusal(directory, this::canRead, NOW);
    }

    @Test
    void anOrdinaryAccountMaySignIn() {
        assertEquals(Optional.empty(), refusal());
    }

    @Test
    void aDisabledAccountIsRefused() {
        set(AccountRestrictions.LOGIN_DISABLED, "TRUE");
        assertEquals(Optional.of("account disabled"), refusal());
    }

    @Test
    void aReEnabledAccountMaySignIn() {
        set(AccountRestrictions.LOGIN_DISABLED, "FALSE");
        assertEquals(Optional.empty(), refusal());
    }

    @Test
    void anIntruderLockoutRefusesUntilItsResetTime() {
        set(AccountRestrictions.LOCKED_BY_INTRUDER, "TRUE");
        set(AccountRestrictions.INTRUDER_RESET_TIME, "20261110163000Z");
        assertEquals(Optional.of("locked by intruder detection"), refusal());

        set(AccountRestrictions.INTRUDER_RESET_TIME, "20261110160000Z");
        assertEquals(Optional.empty(), refusal());
    }

    @Test
    void anIntruderLockoutWithoutAResetTimeRefuses() {
        set(AccountRestrictions.LOCKED_BY_INTRUDER, "TRUE");
        assertEquals(Optional.of("locked by intruder detection"), refusal());
    }

    @Test
    void anExpiredAccountIsRefused() {
        set(AccountRestrictions.EXPIRATION_TIME, "20261110161710Z");
        assertEquals(Optional.of("account expired"), refusal());

        set(AccountRestrictions.EXPIRATION_TIME, "20261231000000Z");
        assertEquals(Optional.empty(), refusal());
    }

    @Test
    void fractionalSecondsAreAccepted() {
        set(AccountRestrictions.EXPIRATION_TIME, "20261110000000.5Z");
        assertEquals(Optional.of("account expired"), refusal());
    }

    @Test
    void valuesItCantUnderstandRefuse() {
        set(AccountRestrictions.LOGIN_DISABLED, "maybe");
        assertThrows(PasskeyStoreException.class, this::refusal);

        directory.values.clear();
        set(AccountRestrictions.EXPIRATION_TIME, "next tuesday");
        assertThrows(PasskeyStoreException.class, this::refusal);
    }

    @Test
    void attributesWithNoValueDoNotRestrictTheAccount() {
        assertEquals(Optional.empty(), refusal());
    }

    @Test
    void anAttributeTheProxyCannotReadRefusesEvenThoughItLooksUnset() {
        for (String attribute : AccountRestrictions.EDIRECTORY_ATTRIBUTES) {
            hidden.clear();
            hidden.add(attribute);
            assertEquals(Optional.of("the user store's proxy account can't read " + attribute), refusal(), attribute);
        }
    }

    @Test
    void rightsThatCannotBeCheckedRefuse() {
        rightsUnknown = true;
        assertThrows(PasskeyStoreException.class, this::refusal);
    }

    @Test
    void aFailedReadRefuses() {
        directory.readsFail = true;
        assertThrows(PasskeyStoreException.class, this::refusal);
    }
}
