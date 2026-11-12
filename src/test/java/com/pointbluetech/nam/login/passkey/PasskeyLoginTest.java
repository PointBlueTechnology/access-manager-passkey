package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Enrolls through {@link PasskeyService}, then signs in with real signatures and no password. */
class PasskeyLoginTest {

    private static final String ORIGIN = "https://login.example.com";
    private static final String ATTR = "pbtPasskeyCredential";
    private static final ObjectMapper JSON = new ObjectMapper();

    private final Clock clock = Clock.fixed(Instant.parse("2026-11-04T12:00:00Z"), ZoneOffset.UTC);
    private final Map<String, Object> session = new HashMap<>();
    private final Map<String, UserDirectory.User> usersByGuid = new HashMap<>();
    private final Map<String, UserDirectory.User> usersById = new HashMap<>();
    private final Map<String, InMemoryAttributes> entries = new HashMap<>();
    private final Properties props = PasskeyConfigTest.minimal();
    private int directorySearches;
    private boolean searchesFail;
    private boolean guidSearchesFail;

    private final UserDirectory directory = new UserDirectory() {
        @Override
        public Optional<User> byGuid(String guid) {
            directorySearches++;
            if (guidSearchesFail) {
                throw new PasskeyStoreException("directory down");
            }
            return Optional.ofNullable(usersByGuid.get(guid));
        }

        @Override
        public Optional<User> byId(String id) {
            directorySearches++;
            if (searchesFail) {
                throw new PasskeyStoreException("directory down");
            }
            return Optional.ofNullable(usersById.get(id));
        }
    };

    private VirtualAuthenticator alice;
    private VirtualAuthenticator bob;

    @BeforeEach
    void setUp() throws Exception {
        props.setProperty("PASSKEY_LDAP_ATTRIBUTE", ATTR);
        alice = enroll("alice", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1);
        bob = enroll("bob", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 2);
        addUser("nopasskeys", "cccccccccccccccccccccccccccccccc");
        props.setProperty("MODE", "LOGIN");
        session.clear();
    }

    @Test
    void anyEnrolledUserCanSignInWithNoIdEntered() throws Exception {
        assertEquals("alice", login().finish(alice.get(login().startUsernameless())).account().name());
        assertEquals("bob", login().finish(bob.get(login().startUsernameless())).account().name());
    }

    @Test
    void usernamelessOptionsListNoCredentialsAndRequireUserVerification() throws Exception {
        JsonNode options = publicKey(login().startUsernameless());

        assertEquals(0, options.path("allowCredentials").size());
        assertEquals("required", options.path("userVerification").asText());
    }

    @Test
    void userCanSignInWithIdFirst() throws Exception {
        String options = login().startForId(" alice ");

        assertEquals(alice.id().getBase64Url(), publicKey(options).get("allowCredentials").get(0).get("id").asText());
        assertEquals("alice", login().finish(alice.get(options)).account().name());
    }

    @Test
    void idFirstOnlyAcceptsThatUsersPasskey() throws Exception {
        String options = login().startForId("alice");

        assertFails(bob.get(options));
    }

    @Test
    void signInRequiresUserVerification() throws Exception {
        alice.userVerified = false;

        assertFails(alice.get(login().startUsernameless()));
    }

    @Test
    void responseClaimingAnotherUsersHandleIsRejected() throws Exception {
        String options = login().startUsernameless();
        alice.userHandle = bob.userHandle;

        assertFails(alice.get(options));
    }

    @Test
    void responseWithAnUnknownOrHostileHandleIsRejected() throws Exception {
        String options = login().startUsernameless();
        alice.userHandle = "*)(objectClass=*".getBytes(StandardCharsets.UTF_8);

        assertFails(alice.get(options));
    }

    @Test
    void usernamelessResponseWithNoHandleIsRejected() throws Exception {
        String options = login().startUsernameless();
        alice.userHandle = null;

        assertFails(alice.get(options));
    }

    @Test
    void replayIsRejected() throws Exception {
        String response = alice.get(login().startUsernameless());
        login().finish(response);

        assertFails(response);
    }

    @Test
    void signInFromAnotherSiteIsRejected() throws Exception {
        VirtualAuthenticator phished = new VirtualAuthenticator("https://evil.example.org", "example.com", 1);
        phished.userHandle = alice.userHandle;

        assertFails(phished.get(login().startUsernameless()));
    }

    @Test
    void unknownIdAndIdWithNoPasskeysLookLikeARealUser() throws Exception {
        JsonNode real = publicKey(login().startForId("alice"));
        JsonNode unknown = publicKey(login().startForId("nobody"));
        JsonNode noPasskeys = publicKey(login().startForId("nopasskeys"));

        for (JsonNode decoy : new JsonNode[] {unknown, noPasskeys}) {
            assertEquals(1, decoy.get("allowCredentials").size());
            assertEquals(real.fieldNames().next(), decoy.fieldNames().next());
            assertEquals(real.get("userVerification"), decoy.get("userVerification"));
            assertEquals(real.get("allowCredentials").get(0).get("type"), decoy.get("allowCredentials").get(0).get("type"));
        }
        assertNotEquals(allowedId(unknown), allowedId(noPasskeys));
    }

    @Test
    void decoyStaysTheSameForAnIdSoRepeatingItRevealsNothing() throws Exception {
        assertEquals(allowedId(publicKey(login().startForId("nobody"))), allowedId(publicKey(login().startForId("NOBODY"))));
    }

    @Test
    void decoyComesFromThePepperSoEveryNodeGivesTheSameOne() throws Exception {
        String withoutPepper = allowedId(publicKey(login().startForId("nobody")));
        props.setProperty("RECOVERY_PEPPER", "a-pepper-shared-by-every-idp-node-0001");
        String first = allowedId(publicKey(login().startForId("nobody")));
        // A separate repository stands in for another node: nothing per-JVM goes into the decoy
        assertEquals(first, allowedId(publicKey(login().startForId("nobody"))));
        assertNotEquals(withoutPepper, first);

        props.setProperty("RECOVERY_PEPPER", "a-different-pepper-for-another-site-0002");
        assertNotEquals(first, allowedId(publicKey(login().startForId("nobody"))));
    }

    @Test
    void passkeyCannotSignInAgainstADecoy() throws Exception {
        assertFails(alice.get(login().startForId("nobody")));
    }

    @Test
    void oversizedIdIsNotSearched() throws Exception {
        directorySearches = 0;

        login().startForId("x".repeat(257));

        assertEquals(0, directorySearches);
    }

    @Test
    void signInCountsAsProvingAPasskeyForTheManagePage() throws Exception {
        login().finish(alice.get(login().startUsernameless()));

        assertTrue(new CeremonyState(sessionMap(), "other-method", guidOf(alice), 300, clock).verifiedWithin(300));
        assertFalse(new CeremonyState(sessionMap(), "other-method", guidOf(bob), 300, clock).verifiedWithin(300));
    }

    @Test
    void signInRecordsLastUsed() throws Exception {
        login().finish(alice.get(login().startUsernameless()));

        assertEquals(clock.instant(), usersByGuid.get(guidOf(alice)).store().load().get(0).lastUsed());
    }

    @Test
    void failingToRecordUseDoesNotFailTheSignIn() throws Exception {
        String response = alice.get(login().startUsernameless());
        entries.get(guidOf(alice)).writesFail = true;

        assertEquals("alice", login().finish(response).account().name());
    }

    @Test
    void directoryOutageIsNotReportedAsAFailedPasskey() throws Exception {
        String options = login().startUsernameless();
        String response = alice.get(options);
        entries.get(guidOf(alice)).readsFail = true;

        assertThrows(PasskeyStoreException.class, () -> login().finish(response));
    }

    @Test
    void failedLookupIsNotTreatedAsAnUnknownUser() {
        searchesFail = true;

        // No decoy: the caller must be told the lookup failed
        assertThrows(PasskeyStoreException.class, () -> login().startForId("alice"));
    }

    @Test
    void aRemovedPasskeyIsReportedAsUnregistered() throws Exception {
        VirtualAuthenticator[] keys = enrollTwo("carol", "dddddddddddddddddddddddddddddddd", 3, 4);
        removePasskey("dddddddddddddddddddddddddddddddd", keys[0]);
        String response = keys[0].get(login().startUsernameless());

        assertFails(response);
        assertEquals(Optional.of(keys[0].id().getBase64Url()), login().unregisteredCredential(response));
    }

    @Test
    void aRegisteredPasskeyIsNeverReportedEvenWhenItsSignInFails() throws Exception {
        alice.userVerified = false;
        String response = alice.get(login().startUsernameless());

        assertFails(response);
        assertEquals(Optional.empty(), login().unregisteredCredential(response));
    }

    @Test
    void nothingIsReportedForAUserWithNoPasskeysLeft() throws Exception {
        // As when every passkey was removed, or the method reads the wrong attribute
        removePasskey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", alice);
        String response = alice.get(login().startUsernameless());

        assertFails(response);
        assertEquals(Optional.empty(), login().unregisteredCredential(response));
    }

    @Test
    void nothingIsReportedForAnUnknownOrMissingUserHandle() throws Exception {
        String options = login().startUsernameless();
        alice.userHandle = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".getBytes(StandardCharsets.UTF_8);
        assertEquals(Optional.empty(), login().unregisteredCredential(alice.get(options)));

        alice.userHandle = null;
        assertEquals(Optional.empty(), login().unregisteredCredential(alice.get(options)));
    }

    @Test
    void nothingIsReportedWhenTheDirectoryCannotBeRead() throws Exception {
        VirtualAuthenticator[] keys = enrollTwo("carol", "dddddddddddddddddddddddddddddddd", 3, 4);
        removePasskey("dddddddddddddddddddddddddddddddd", keys[0]);
        String response = keys[0].get(login().startUsernameless());
        guidSearchesFail = true;

        assertEquals(Optional.empty(), login().unregisteredCredential(response));
        assertEquals(Optional.empty(), login().unregisteredCredential("not json"));
    }

    /** Two passkeys for one user, both registered in the same first-passkey login. */
    private VirtualAuthenticator[] enrollTwo(String name, String guid, long firstSeed, long secondSeed)
            throws Exception {
        props.setProperty("MODE", "MFA");
        UserDirectory.User user = addUser(name, guid);
        CeremonyState state = new CeremonyState(sessionMap(), "enroll", guid, 300, clock);
        PasskeyService service = new PasskeyService(PasskeyConfig.from(props), user.account(), user.store(), state, clock);
        VirtualAuthenticator first = new VirtualAuthenticator(ORIGIN, "example.com", firstSeed);
        VirtualAuthenticator second = new VirtualAuthenticator(ORIGIN, "example.com", secondSeed);
        service.finishRegistration(first.create(service.startRegistration()), "First");
        service.finishRegistration(second.create(service.startRegistration()), "Second");
        props.setProperty("MODE", "LOGIN");
        session.clear();
        return new VirtualAuthenticator[] {first, second};
    }

    private void removePasskey(String guid, VirtualAuthenticator authenticator) {
        usersByGuid.get(guid).store().update(records -> {
            java.util.List<PasskeyRecord> kept = new java.util.ArrayList<>(records);
            kept.removeIf(record -> record.credentialId().equals(authenticator.id()));
            return kept;
        });
    }

    private void assertFails(String response) {
        CeremonyFailedException e = assertThrows(CeremonyFailedException.class, () -> login().finish(response));
        assertEquals("error.loginFailed", e.messageKey());
    }

    private static String allowedId(JsonNode options) {
        return options.get("allowCredentials").get(0).get("id").asText();
    }

    private static JsonNode publicKey(String options) throws Exception {
        return JSON.readTree(options).get("publicKey");
    }

    private static String guidOf(VirtualAuthenticator authenticator) {
        return new String(authenticator.userHandle, StandardCharsets.UTF_8);
    }

    private PasskeyLogin login() {
        PasskeyConfig config = PasskeyConfig.from(props);
        return new PasskeyLogin(config, directory, new CeremonyState(sessionMap(), "login", "login", 300, clock), clock);
    }

    private UserDirectory.User addUser(String name, String guid) {
        InMemoryAttributes attributes = new InMemoryAttributes();
        entries.put(guid, attributes);
        UserDirectory.User user = new UserDirectory.User(new UserAccount(guid, name, name),
                new PasskeyStore(attributes, ATTR, ""), name);
        usersByGuid.put(guid, user);
        usersById.put(name, user);
        return user;
    }

    private VirtualAuthenticator enroll(String name, String guid, long seed) throws Exception {
        UserDirectory.User user = addUser(name, guid);
        VirtualAuthenticator authenticator = new VirtualAuthenticator(ORIGIN, "example.com", seed);
        CeremonyState state = new CeremonyState(sessionMap(), "enroll", guid, 300, clock);
        PasskeyService service = new PasskeyService(PasskeyConfig.from(props), user.account(), user.store(), state, clock);
        service.finishRegistration(authenticator.create(service.startRegistration()), "Key");
        return authenticator;
    }

    private CeremonyState.Session sessionMap() {
        return new CeremonyState.Session() {
            @Override
            public Object get(String key) {
                return session.get(key);
            }

            @Override
            public void put(String key, Object value) {
                session.put(key, value);
            }
        };
    }
}
