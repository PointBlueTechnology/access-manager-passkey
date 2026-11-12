package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ReadRightsCacheTest {

    private Instant now = Instant.parse("2026-11-12T12:00:00Z");
    private final Clock clock = new Clock() {
        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    };
    private final ReadRightsCache cache = new ReadRightsCache(clock, 3);
    private final Map<String, Integer> asked = new HashMap<>();
    private boolean readable = true;
    private boolean fails;

    private AccountRestrictions.ReadRights directory() {
        return attribute -> {
            asked.merge(attribute, 1, Integer::sum);
            if (fails) {
                throw new PasskeyStoreException("Get Effective Privileges failed");
            }
            return readable;
        };
    }

    @Test
    void aConfirmedRightIsKeptForTheContainerUntilItExpires() {
        AccountRestrictions.ReadRights rights = cache.cached("proxy\nou=a", 3600, directory());
        assertTrue(rights.canRead("loginDisabled"));
        assertTrue(cache.cached("proxy\nou=a", 3600, directory()).canRead("loginDisabled"));
        assertEquals(1, asked.get("loginDisabled"));

        now = now.plusSeconds(3600);
        assertTrue(cache.cached("proxy\nou=a", 3600, directory()).canRead("loginDisabled"));
        assertEquals(2, asked.get("loginDisabled"));
    }

    @Test
    void eachContainerAndAttributeIsAskedSeparately() {
        cache.cached("proxy\nou=a", 3600, directory()).canRead("loginDisabled");
        cache.cached("proxy\nou=b", 3600, directory()).canRead("loginDisabled");
        cache.cached("proxy\nou=a", 3600, directory()).canRead("lockedByIntruder");
        assertEquals(2, asked.get("loginDisabled"));
        assertEquals(1, asked.get("lockedByIntruder"));
    }

    @Test
    void aRefusalIsNeverKeptSoAFixedAclWorksAtOnce() {
        readable = false;
        assertFalse(cache.cached("proxy\nou=a", 3600, directory()).canRead("loginDisabled"));
        assertFalse(cache.cached("proxy\nou=a", 3600, directory()).canRead("loginDisabled"));
        readable = true;
        assertTrue(cache.cached("proxy\nou=a", 3600, directory()).canRead("loginDisabled"));
        assertEquals(3, asked.get("loginDisabled"));
    }

    @Test
    void aFailedCheckIsNotKept() {
        fails = true;
        assertThrows(PasskeyStoreException.class, () -> cache.cached("proxy\nou=a", 3600, directory()).canRead("a"));
        fails = false;
        assertTrue(cache.cached("proxy\nou=a", 3600, directory()).canRead("a"));
        assertEquals(2, asked.get("a"));
    }

    @Test
    void aRightThatWasWithdrawnIsAskedAgainOnceItsTimeIsUp() {
        assertTrue(cache.cached("proxy\nou=a", 60, directory()).canRead("a"));
        readable = false;
        now = now.plusSeconds(61);
        assertFalse(cache.cached("proxy\nou=a", 60, directory()).canRead("a"));
        // And the refusal replaced what was kept
        readable = true;
        assertTrue(cache.cached("proxy\nou=a", 60, directory()).canRead("a"));
        assertEquals(3, asked.get("a"));
    }

    @Test
    void itStaysBounded() {
        for (int i = 0; i < 10; i++) {
            assertTrue(cache.cached("proxy\nou=" + i, 3600, directory()).canRead("a"));
        }
        assertEquals(10, asked.get("a"));
    }
}
