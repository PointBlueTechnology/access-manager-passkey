package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class PasswordManagerSignalsTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String GUID = "50533b75ea2eed44908250533b75ea2e";

    @Test
    void acceptedListsEveryPasskeyWithTheUserHandleAndNames() throws Exception {
        UserAccount account = new UserAccount(GUID, "jsmith", "Jo Smith");
        List<PasskeyRecord> passkeys = passkeys(account, 2);

        JsonNode json = JSON.readTree(new PasswordManagerSignals("example.com").accepted(account, passkeys).toScriptJson());

        JsonNode accepted = json.get("accepted");
        assertEquals("example.com", accepted.get("rpId").asText());
        assertEquals(account.userHandle().getBase64Url(), accepted.get("userId").asText());
        assertEquals(2, accepted.get("allAcceptedCredentialIds").size());
        assertEquals(passkeys.get(0).credentialId().getBase64Url(), accepted.get("allAcceptedCredentialIds").get(0).asText());
        assertEquals(passkeys.get(1).credentialId().getBase64Url(), accepted.get("allAcceptedCredentialIds").get(1).asText());
        JsonNode user = json.get("user");
        assertEquals(account.userHandle().getBase64Url(), user.get("userId").asText());
        assertEquals("jsmith", user.get("name").asText());
        assertEquals("Jo Smith", user.get("displayName").asText());
        assertFalse(json.has("unknown"));
    }

    @Test
    void anEmptyListIsNeverSent() {
        UserAccount account = new UserAccount(GUID, "jsmith", "Jo Smith");

        assertThrows(IllegalArgumentException.class,
                () -> new PasswordManagerSignals("example.com").accepted(account, List.of()));
    }

    @Test
    void unknownPasskeysAreListedOnTheirOwn() throws Exception {
        PasswordManagerSignals signals = new PasswordManagerSignals("example.com");
        assertTrue(signals.isEmpty());

        JsonNode json = JSON.readTree(signals.unknown("AAAA").unknown("BBBB").toScriptJson());

        assertFalse(signals.isEmpty());
        assertEquals(2, json.get("unknown").size());
        assertEquals("example.com", json.get("unknown").get(0).get("rpId").asText());
        assertEquals("BBBB", json.get("unknown").get(1).get("credentialId").asText());
        assertFalse(json.has("accepted"));
    }

    @Test
    void namesCannotBreakOutOfTheScriptBlock() throws Exception {
        UserAccount account = new UserAccount(GUID, "</script><script>alert(1)</script>", "A & B");

        String json = new PasswordManagerSignals("example.com").accepted(account, passkeys(account, 1)).toScriptJson();

        assertFalse(json.contains("<"));
        assertFalse(json.contains(">"));
        assertFalse(json.contains("&"));
        assertEquals("A & B", JSON.readTree(json).get("user").get("displayName").asText());
    }

    /** Real records, registered through the service against a software authenticator. */
    private static List<PasskeyRecord> passkeys(UserAccount account, int count) throws Exception {
        Properties props = PasskeyConfigTest.minimal();
        Map<String, Object> session = new HashMap<>();
        CeremonyState state = new CeremonyState(new CeremonyState.Session() {
            @Override
            public Object get(String key) {
                return session.get(key);
            }

            @Override
            public void put(String key, Object value) {
                session.put(key, value);
            }
        }, "card", account.guid(), 300, Clock.fixed(Instant.parse("2026-11-04T12:00:00Z"), ZoneOffset.UTC));
        PasskeyStore store = new PasskeyStore(new InMemoryAttributes(), "pbtPasskeyCredential", "");
        Clock clock = Clock.fixed(Instant.parse("2026-11-04T12:00:00Z"), ZoneOffset.UTC);
        PasskeyService service = new PasskeyService(PasskeyConfig.from(props), account, store, state, clock);
        for (int i = 1; i <= count; i++) {
            VirtualAuthenticator authenticator = new VirtualAuthenticator("https://login.example.com", "example.com", i);
            service.finishRegistration(authenticator.create(service.startRegistration()), "Key " + i);
        }
        return store.load();
    }
}
