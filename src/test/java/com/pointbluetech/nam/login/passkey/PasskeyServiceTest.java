package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Runs real ceremonies, with real signatures, against the Yubico library. */
class PasskeyServiceTest {

    private static final String ORIGIN = "https://login.example.com";
    private static final String RP_ID = "example.com";
    private static final String GUID = "50533b75ea2eed44908250533b75ea2e";

    private final InMemoryAttributes directory = new InMemoryAttributes();
    private final Map<String, Object> session = new HashMap<>();
    private final Properties props = PasskeyConfigTest.minimal();
    private MutableClock clock;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-11-04T12:00:00Z"));
        props.setProperty("PASSKEY_LDAP_ATTRIBUTE", "pbtPasskeyCredential");
        props.setProperty("PASSKEY_AUX_CLASS", "pbtPasskeyUser");
    }

    @Test
    void enrollTwoPasskeysThenSignInWithEither() throws Exception {
        VirtualAuthenticator first = authenticator(1);
        VirtualAuthenticator second = authenticator(2);

        PasskeyService service = service();
        assertTrue(service.passkeys().isEmpty());
        service.finishRegistration(first.create(service.startRegistration()), "Laptop");
        service.finishRegistration(second.create(service.startRegistration()), "Phone");

        assertEquals(2, directory.passkeyValues().size());
        assertTrue(directory.values.get("objectClass").contains("pbtPasskeyUser"));

        state().setEnrolling(false);
        service().finishAssertion(first.get(service().startAssertion()));
        service().finishAssertion(second.get(service().startAssertion()));
    }

    @Test
    void offersOnlyAlgorithmsThisJvmCanVerifyWithEs256First() throws Exception {
        String options = service().startRegistration();
        var offered = new com.fasterxml.jackson.databind.ObjectMapper().readTree(options)
                .get("publicKey").get("pubKeyCredParams");

        assertEquals(-7, offered.get(0).get("alg").asInt());
        assertEquals(RelyingPartyFactory.algorithms().size(), offered.size());
        assertFalse(options.contains("-48"), options);
    }

    @Test
    void assertionOffersAllOfTheUsersPasskeys() throws Exception {
        VirtualAuthenticator first = enroll(1);
        String options = service().startAssertion();

        assertTrue(options.contains(first.id().getBase64Url()), options);
    }

    @Test
    void replayedAssertionIsRejected() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        String response = authenticator.get(service().startAssertion());
        service().finishAssertion(response);

        CeremonyFailedException e = assertThrows(CeremonyFailedException.class,
                () -> service().finishAssertion(response));
        assertEquals("error.expired", e.messageKey());
    }

    @Test
    void assertionFromAnEarlierChallengeIsRejected() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        String stale = authenticator.get(service().startAssertion());
        service().startAssertion();

        CeremonyFailedException e = assertThrows(CeremonyFailedException.class,
                () -> service().finishAssertion(stale));
        assertEquals("error.verify", e.messageKey());
    }

    @Test
    void badSignatureIsRejected() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        String response = VirtualAuthenticator.tamper(authenticator.get(service().startAssertion()));

        assertVerifyFails(response);
    }

    @Test
    void assertionFromAnotherSiteIsRejected() throws Exception {
        VirtualAuthenticator enrolled = enroll(1);
        VirtualAuthenticator phished = new VirtualAuthenticator("https://evil.example.org", RP_ID, 1);
        phished.userHandle = enrolled.userHandle;

        // Same credential ID, but the origin the browser reports is the phishing site's
        assertVerifyFails(phished.get(service().startAssertion()));
    }

    @Test
    void assertionWithAnUnknownKeyIsRejected() throws Exception {
        enroll(1);
        VirtualAuthenticator stranger = authenticator(99);
        stranger.userHandle = GUID.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        assertVerifyFails(stranger.get(service().startAssertion()));
    }

    @Test
    void wrongKeyForAKnownCredentialIdIsRejected() throws Exception {
        VirtualAuthenticator enrolled = enroll(1);
        // Same seed gives the same credential ID, but this has a new key pair
        VirtualAuthenticator forged = authenticator(1);
        forged.userHandle = enrolled.userHandle;

        assertVerifyFails(forged.get(service().startAssertion()));
    }

    @Test
    void signCountGoingBackwardsIsRejected() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        authenticator.counter = 10;
        service().finishAssertion(authenticator.get(service().startAssertion()));

        authenticator.counter = 3;
        assertVerifyFails(authenticator.get(service().startAssertion()));
    }

    @Test
    void expiredChallengeIsRejected() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        String response = authenticator.get(service().startAssertion());
        clock.advance(Duration.ofSeconds(301));

        CeremonyFailedException e = assertThrows(CeremonyFailedException.class,
                () -> service().finishAssertion(response));
        assertEquals("error.expired", e.messageKey());
    }

    @Test
    void passwordAloneCannotAddAPasskeyToAnAccountThatHasOne() throws Exception {
        enroll(1);
        state().setEnrolling(false); // a later login, with only the password behind it
        VirtualAuthenticator attacker = authenticator(2);

        assertEquals("error.registerNotAllowed", assertThrows(CeremonyFailedException.class,
                () -> service().startRegistration()).messageKey());

        // Nor by finishing a registration begun before the first passkey appeared
        Map<String, Object> otherLogin = new HashMap<>();
        CeremonyState otherState = new CeremonyState(sessionOf(otherLogin), "card", GUID, 300, clock);
        InMemoryAttributes empty = new InMemoryAttributes();
        String options = serviceFor(empty, otherState).startRegistration();
        String response = attacker.create(options);
        CeremonyFailedException e = assertThrows(CeremonyFailedException.class,
                () -> serviceFor(directory, otherState).finishRegistration(response, "Attacker"));

        assertEquals("error.registerNotAllowed", e.messageKey());
        assertEquals(1, directory.passkeyValues().size());
    }

    @Test
    void enrollmentCanBeTurnedOff() throws Exception {
        props.setProperty("ENROLL_IF_NONE", "false");

        assertEquals("error.registerNotAllowed", assertThrows(CeremonyFailedException.class,
                () -> service().startRegistration()).messageKey());
    }

    @Test
    void passkeyLimitIsEnforced() throws Exception {
        props.setProperty("MAX_PASSKEYS", "1");
        VirtualAuthenticator first = enroll(1);
        assertTrue(state().enrolling());

        assertEquals("error.limit", assertThrows(CeremonyFailedException.class,
                () -> service().startRegistration()).messageKey());
        assertEquals(first.id(), service().passkeys().get(0).credentialId());
    }

    @Test
    void registeringTheSameCredentialTwiceIsRejected() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);

        String response = authenticator.create(service().startRegistration());
        assertVerifyRegistrationFails(response);
        assertEquals(1, directory.passkeyValues().size());
    }

    @Test
    void registrationWithoutUserVerificationIsRejected() throws Exception {
        VirtualAuthenticator authenticator = authenticator(1);
        authenticator.userVerified = false;

        assertVerifyRegistrationFails(authenticator.create(service().startRegistration()));
    }

    @Test
    void nonDiscoverableCredentialIsRefusedWhenAResidentKeyIsRequired() throws Exception {
        VirtualAuthenticator authenticator = authenticator(1);
        authenticator.reportDiscoverable = false;

        CeremonyFailedException e = assertThrows(CeremonyFailedException.class,
                () -> service().finishRegistration(authenticator.create(service().startRegistration()), null));
        assertEquals("error.notDiscoverable", e.messageKey());
        assertTrue(directory.passkeyValues().isEmpty());
    }

    @Test
    void credentialWithUnknownDiscoverabilityIsAccepted() throws Exception {
        VirtualAuthenticator authenticator = authenticator(1);
        authenticator.reportDiscoverable = null;

        service().finishRegistration(authenticator.create(service().startRegistration()), null);
        assertEquals(1, directory.passkeyValues().size());
    }

    @Test
    void readFailureNeverLooksLikeNoPasskeys() throws Exception {
        enroll(1);
        directory.readsFail = true;
        int writes = directory.writes;

        assertThrows(PasskeyStoreException.class, () -> service().passkeys());
        assertThrows(PasskeyStoreException.class, () -> service().startRegistration());
        assertEquals(writes, directory.writes);
    }

    @Test
    void failingToRecordUseDoesNotFailTheSignIn() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        String response = authenticator.get(service().startAssertion());
        directory.writesFail = true;

        service().finishAssertion(response);
    }

    @Test
    void signInWritesToTheDirectoryOnlyWhenSomethingChanged() throws Exception {
        VirtualAuthenticator synced = authenticator(1);
        synced.synced = true;
        service().finishRegistration(synced.create(service().startRegistration()), null);
        state().setEnrolling(false);
        // A synced passkey has a counter stuck at 0
        synced.counter = -1;

        int before = directory.writes;
        signIn(synced);
        assertEquals(before + 1, directory.writes, "first use records lastUsed");

        synced.counter = -1;
        signIn(synced);
        assertEquals(before + 1, directory.writes, "nothing changed within the interval");

        clock.advance(Duration.ofHours(25));
        synced.counter = -1;
        signIn(synced);
        assertEquals(before + 2, directory.writes, "lastUsed has gone stale");
    }

    @Test
    void namesAreCleanedAndDefaulted() throws Exception {
        PasskeyService service = service();
        PasskeyRecord unnamed = service.finishRegistration(authenticator(1).create(service.startRegistration()), "  ");
        PasskeyRecord messy = service.finishRegistration(
                authenticator(2).create(service.startRegistration()), " Work\tlaptop\n" + "x".repeat(80));

        assertEquals("Passkey 2026-11-04", unnamed.name());
        assertEquals(PasskeyService.MAX_NAME_LENGTH, messy.name().length());
        assertFalse(messy.name().contains("\n"));
    }

    @Test
    void defaultNameUsesTheProviderWhenItIsKnown() throws Exception {
        VirtualAuthenticator google = authenticator(1);
        google.aaguid = com.yubico.webauthn.data.ByteArray.fromHex("ea9b8d664d011d213ce4b6b48cb575d4").getBytes();
        PasskeyService service = service();

        PasskeyRecord record = service.finishRegistration(google.create(service.startRegistration()), null);

        assertEquals("Google Password Manager 2026-11-04", record.name());
        assertEquals("Google Password Manager", service.views(service.passkeys()).get(0).provider());
    }

    @Test
    void managePageIsLockedUntilAPasskeyIsProvedEvenWithThePassword() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        session.clear(); // a new login, with only the password behind it
        props.setProperty("MODE", "MANAGE");
        PasskeyService service = service();

        assertFalse(service.manageUnlocked(service.passkeys()));
        String id = authenticator.id().getBase64Url();
        assertEquals("error.confirmFirst", assertThrows(CeremonyFailedException.class,
                () -> service().rename(id, "Mine now")).messageKey());
        assertEquals("error.confirmFirst", assertThrows(CeremonyFailedException.class,
                () -> service().delete(id)).messageKey());
        assertEquals("error.registerNotAllowed", assertThrows(CeremonyFailedException.class,
                () -> service().startRegistration()).messageKey());
        assertEquals(1, directory.passkeyValues().size());

        signIn(authenticator);
        assertTrue(service().manageUnlocked(service().passkeys()));
    }

    @Test
    void manageAddsRenamesAndRemovesAcrossSeveralPasskeys() throws Exception {
        VirtualAuthenticator first = enroll(1);
        session.clear();
        props.setProperty("MODE", "MANAGE");
        signIn(first);

        VirtualAuthenticator second = authenticator(2);
        service().finishRegistration(second.create(service().startRegistration()), "Phone");
        VirtualAuthenticator third = authenticator(3);
        service().finishRegistration(third.create(service().startRegistration()), "Key");
        assertEquals(3, service().passkeys().size());

        service().rename(second.id().getBase64Url(), "  Work\tphone ");
        assertEquals("Work phone", service().passkeys().get(1).name());
        assertEquals("Test", service().passkeys().get(0).name());

        service().delete(first.id().getBase64Url());
        assertEquals(2, service().passkeys().size());
        assertEquals("Work phone", service().passkeys().get(0).name());

        // A removed passkey no longer signs in; the others still do
        assertVerifyFails(first.get(service().startAssertion()));
        signIn(second);
        signIn(third);
    }

    @Test
    void manageLocksAgainOnceTheProofAgesOut() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        session.clear();
        props.setProperty("MODE", "MANAGE");
        signIn(authenticator);
        String id = authenticator.id().getBase64Url();

        clock.advance(Duration.ofSeconds(300));
        assertTrue(service().manageUnlocked(service().passkeys()));
        clock.advance(Duration.ofSeconds(1));

        assertFalse(service().manageUnlocked(service().passkeys()));
        assertEquals("error.confirmFirst", assertThrows(CeremonyFailedException.class,
                () -> service().delete(id)).messageKey());
        assertEquals("error.registerNotAllowed", assertThrows(CeremonyFailedException.class,
                () -> service().startRegistration()).messageKey());
    }

    @Test
    void registrationBegunWhileUnlockedCannotFinishAfterTheProofAgesOut() throws Exception {
        props.setProperty("CHALLENGE_TTL_SEC", "3600");
        VirtualAuthenticator authenticator = enroll(1);
        session.clear();
        props.setProperty("MODE", "MANAGE");
        signIn(authenticator);
        CeremonyState longLived = new CeremonyState(sessionOf(session), "card", GUID, 3600, clock);
        String response = authenticator(2).create(serviceFor(directory, longLived).startRegistration());

        clock.advance(Duration.ofSeconds(301));

        assertEquals("error.registerNotAllowed", assertThrows(CeremonyFailedException.class,
                () -> serviceFor(directory, longLived).finishRegistration(response, null)).messageKey());
    }

    @Test
    void signInWithoutUserVerificationDoesNotUnlockManage() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        session.clear();
        authenticator.userVerified = false; // accepted in MFA mode, where it's only "preferred"
        signIn(authenticator);

        props.setProperty("MODE", "MANAGE");
        assertFalse(service().manageUnlocked(service().passkeys()));
    }

    @Test
    void manageRequiresUserVerificationWhenConfirming() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        session.clear();
        props.setProperty("MODE", "MANAGE");
        authenticator.userVerified = false;

        assertVerifyFails(authenticator.get(service().startAssertion()));
        assertFalse(service().manageUnlocked(service().passkeys()));
    }

    @Test
    void verifiedByAnotherUserDoesNotUnlock() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        signIn(authenticator);
        props.setProperty("MODE", "MANAGE");

        CeremonyState otherUser = new CeremonyState(sessionOf(session), "card", "someone-else", 300, clock);
        assertFalse(otherUser.verifiedWithin(300));
    }

    @Test
    void userWithNoPasskeysCanEnrollFromManageOnlyWhenEnrollmentIsOn() throws Exception {
        props.setProperty("MODE", "MANAGE");
        assertTrue(service().manageUnlocked(service().passkeys()));
        service().finishRegistration(authenticator(1).create(service().startRegistration()), "First");
        assertTrue(service().manageUnlocked(service().passkeys()), "creating it counts as proving it");

        directory.values.remove("pbtPasskeyCredential");
        session.clear();
        props.setProperty("ENROLL_IF_NONE", "false");
        assertFalse(service().manageUnlocked(service().passkeys()));
    }

    @Test
    void lastPasskeyCanBeProtected() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        props.setProperty("MODE", "MANAGE");
        props.setProperty("REQUIRE_ONE", "true");
        signIn(authenticator);
        String id = authenticator.id().getBase64Url();

        assertEquals("error.lastPasskey", assertThrows(CeremonyFailedException.class,
                () -> service().delete(id)).messageKey());

        props.setProperty("REQUIRE_ONE", "false");
        service().delete(id);
        assertFalse(directory.values.containsKey("pbtPasskeyCredential"));
    }

    @Test
    void manageRejectsUnknownPasskeysAndBlankNames() throws Exception {
        VirtualAuthenticator authenticator = enroll(1);
        props.setProperty("MODE", "MANAGE");
        signIn(authenticator);

        assertEquals("error.notFound", assertThrows(CeremonyFailedException.class,
                () -> service().delete("AAAA")).messageKey());
        assertEquals("error.nameRequired", assertThrows(CeremonyFailedException.class,
                () -> service().rename(authenticator.id().getBase64Url(), "   ")).messageKey());
    }

    @Test
    void recoveredUserMustRegisterAndTheNewPasskeyIsMarked() throws Exception {
        VirtualAuthenticator lost = enroll(1);
        session.clear(); // password only, every passkey lost
        props.setProperty("MODE", "RECOVERY");
        props.setProperty("RECOVERY_PEPPER", "0123456789abcdef0123456789abcdef");

        assertEquals("error.registerNotAllowed", assertThrows(CeremonyFailedException.class,
                () -> service().startRegistration()).messageKey(), "no code yet");

        state().setRecovered();
        VirtualAuthenticator replacement = authenticator(2);
        PasskeyRecord record = service().finishRegistration(replacement.create(service().startRegistration()), "New");
        state().setRecoveryEnrolled();

        assertTrue(record.viaRecovery());
        assertTrue(service().manageUnlocked(service().passkeys()), "may now remove the lost one");
        service().delete(lost.id().getBase64Url());
        signIn(replacement);
    }

    @Test
    void recoveryIsNotStoppedByThePasskeyLimit() throws Exception {
        props.setProperty("MAX_PASSKEYS", "1");
        enroll(1);
        session.clear();
        props.setProperty("MODE", "RECOVERY");
        props.setProperty("RECOVERY_PEPPER", "0123456789abcdef0123456789abcdef");
        state().setRecovered();

        service().finishRegistration(authenticator(2).create(service().startRegistration()), "New");

        assertEquals(2, service().passkeys().size());
    }

    @Test
    void recoveryFlagSurvivesLaterWrites() throws Exception {
        props.setProperty("MODE", "RECOVERY");
        props.setProperty("RECOVERY_PEPPER", "0123456789abcdef0123456789abcdef");
        state().setRecovered();
        VirtualAuthenticator authenticator = authenticator(1);
        service().finishRegistration(authenticator.create(service().startRegistration()), "New");

        service().rename(authenticator.id().getBase64Url(), "Renamed");

        assertTrue(service().passkeys().get(0).viaRecovery());
    }

    private VirtualAuthenticator enroll(long seed) throws Exception {
        VirtualAuthenticator authenticator = authenticator(seed);
        service().finishRegistration(authenticator.create(service().startRegistration()), "Test");
        return authenticator;
    }

    private void signIn(VirtualAuthenticator authenticator) throws Exception {
        service().finishAssertion(authenticator.get(service().startAssertion()));
    }

    private void assertVerifyFails(String response) {
        CeremonyFailedException e = assertThrows(CeremonyFailedException.class,
                () -> service().finishAssertion(response));
        assertEquals("error.verify", e.messageKey());
    }

    private void assertVerifyRegistrationFails(String response) {
        CeremonyFailedException e = assertThrows(CeremonyFailedException.class,
                () -> service().finishRegistration(response, null));
        assertEquals("error.verify", e.messageKey());
    }

    private VirtualAuthenticator authenticator(long seed) throws Exception {
        return new VirtualAuthenticator(ORIGIN, RP_ID, seed);
    }

    /** A new service per step, as NAM creates new class instances; only the session carries over. */
    private PasskeyService service() {
        return serviceFor(directory, state());
    }

    private PasskeyService serviceFor(InMemoryAttributes attributes, CeremonyState state) {
        PasskeyConfig config = PasskeyConfig.from(props);
        return new PasskeyService(config, new UserAccount(GUID, "alice", "Alice"),
                new PasskeyStore(attributes, config.passkeyAttribute(), config.auxClass()), state, clock);
    }

    private CeremonyState state() {
        return new CeremonyState(sessionOf(session), "card", GUID, 300, clock);
    }

    private static CeremonyState.Session sessionOf(Map<String, Object> map) {
        return new CeremonyState.Session() {
            @Override
            public Object get(String key) {
                return map.get(key);
            }

            @Override
            public void put(String key, Object value) {
                map.put(key, value);
            }
        };
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }

    @Test
    void firstPasskeyWaitsForEveryEnrollmentGate() throws Exception {
        props.setProperty("ENROLL_GATES", "email, helpdesk");
        props.setProperty("RECOVERY_PEPPER", "0123456789abcdef0123456789abcdef");
        PasskeyService service = service();

        assertEquals(java.util.List.of(PasskeyConfig.EnrollGate.EMAIL, PasskeyConfig.EnrollGate.HELPDESK),
                service.pendingGates(service.passkeys()));
        assertEquals("error.registerNotAllowed",
                assertThrows(CeremonyFailedException.class, service::startRegistration).messageKey());

        state().passGate("EMAIL");
        assertEquals(java.util.List.of(PasskeyConfig.EnrollGate.HELPDESK), service().pendingGates(service().passkeys()));
        assertThrows(CeremonyFailedException.class, () -> service().startRegistration());

        state().passGate("HELPDESK");
        authenticator(1).create(service().startRegistration());
    }

    @Test
    void gatesDontApplyOnceAUserHasAPasskey() throws Exception {
        enroll(1);
        props.setProperty("ENROLL_GATES", "email");

        assertTrue(service().pendingGates(service().passkeys()).isEmpty());
    }

    private static final byte[] KEY_AAGUID = {(byte) 0xee, (byte) 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13,
            (byte) 0x97, 0x75, 0x3d, (byte) 0xfc, (byte) 0xce, (byte) 0x97, 0x07, 0x2a};
    private static final String KEY_AAGUID_TEXT = "EE882879-721C-4913-9775-3DFCCE97072A";

    private VirtualAuthenticator securityKey(long seed) throws Exception {
        VirtualAuthenticator key = authenticator(seed);
        key.aaguid = KEY_AAGUID.clone();
        return key;
    }

    private String refusal(VirtualAuthenticator authenticator) {
        return assertThrows(CeremonyFailedException.class,
                () -> service().finishRegistration(authenticator.create(service().startRegistration()), "Key"))
                .messageKey();
    }

    @Test
    void allowListTakesAListedKeyWithTrustedAttestation() throws Exception {
        TestAttestation vendor = new TestAttestation("Vendor");
        props.setProperty("ALLOWED_AAGUIDS", KEY_AAGUID_TEXT);
        props.setProperty("ATTESTATION_TRUST_ROOTS", vendor.rootPem());
        VirtualAuthenticator key = securityKey(1);
        vendor.attest(key);

        assertTrue(service().startRegistration().contains("\"attestation\":\"direct\""), "asks for attestation");
        PasskeyRecord saved = service().finishRegistration(key.create(service().startRegistration()), "Key");
        assertEquals("ee882879721c491397753dfcce97072a", saved.aaguid());
    }

    @Test
    void allowListRefusesAKeyWithoutAttestation() throws Exception {
        props.setProperty("ALLOWED_AAGUIDS", KEY_AAGUID_TEXT);
        props.setProperty("ATTESTATION_TRUST_ROOTS", new TestAttestation("Vendor").rootPem());

        // A synced passkey, or software claiming the right AAGUID, sends no attestation it can prove
        assertEquals("error.authenticatorNotAllowed", refusal(securityKey(1)));
        assertTrue(directory.passkeyValues().isEmpty());
    }

    @Test
    void allowListRefusesAttestationFromAnotherRoot() throws Exception {
        props.setProperty("ALLOWED_AAGUIDS", KEY_AAGUID_TEXT);
        props.setProperty("ATTESTATION_TRUST_ROOTS", new TestAttestation("Vendor").rootPem());
        VirtualAuthenticator key = securityKey(1);
        new TestAttestation("Impostor").attest(key);

        assertEquals("error.authenticatorNotAllowed", refusal(key));
    }

    @Test
    void allowListRefusesATrustedKeyThatIsntListed() throws Exception {
        TestAttestation vendor = new TestAttestation("Vendor");
        props.setProperty("ALLOWED_AAGUIDS", "11111111-2222-3333-4444-555555555555");
        props.setProperty("ATTESTATION_TRUST_ROOTS", vendor.rootPem());
        VirtualAuthenticator key = securityKey(1);
        vendor.attest(key);

        assertEquals("error.authenticatorNotAllowed", refusal(key));
    }
}
