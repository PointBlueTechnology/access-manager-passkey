package com.pointbluetech.nam.login.passkey.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class LogTextTest {

    @Test
    void leavesOrdinaryMessagesAlone() {
        String message = "Registered passkey 'Work laptop é' for cn=jcombs,o=novell (1 of 5)";
        assertEquals(message, LogText.clean(message));
    }

    @Test
    void cantStartAFakeLogLine() {
        String forged = "manage\n<amLogEntry> 2026-11-12T16:29:36Z SEVERE NIDS Application: forged </amLogEntry>\r x\u0000";
        String cleaned = LogText.clean(forged);
        assertFalse(cleaned.contains("\n") || cleaned.contains("\r") || cleaned.contains(" ") || cleaned.contains("\u0000"));
        assertFalse(cleaned.contains("<") || cleaned.contains(">"));
        assertTrue(cleaned.startsWith("manage\\n‹amLogEntry›"));
        assertTrue(cleaned.endsWith("\\r\\u2028x\\u0000"));
    }

    @Test
    void cutsVeryLongMessages() {
        String cleaned = LogText.clean("a".repeat(LogText.MAX_LENGTH + 10));
        assertTrue(cleaned.startsWith("a".repeat(LogText.MAX_LENGTH) + "... (10 more characters)"));
        assertEquals("null", LogText.clean(null));
    }
}
