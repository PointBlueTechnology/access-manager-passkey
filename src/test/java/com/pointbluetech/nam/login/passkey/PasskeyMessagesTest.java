package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Locale;
import org.junit.jupiter.api.Test;

class PasskeyMessagesTest {

    @Test
    void looksUpTextAndFallsBackToTheKey() {
        assertEquals("Use passkey", PasskeyMessages.get(Locale.FRENCH, "mfa.button"));
        assertEquals("no.such.key", PasskeyMessages.get(Locale.ENGLISH, "no.such.key"));
    }

    @Test
    void scriptTagEscapingKeepsTheJsonMeaningButCannotCloseTheTag() throws Exception {
        String hostile = "{\"name\":\"</script><script>alert(1)</script>&<!--\"}";

        String escaped = PasskeyMessages.jsonForScriptTag(hostile);

        assertFalse(escaped.contains("<"));
        assertFalse(escaped.contains(">"));
        ObjectMapper json = new ObjectMapper();
        assertEquals(json.readTree(hostile), json.readTree(escaped));
    }
}
