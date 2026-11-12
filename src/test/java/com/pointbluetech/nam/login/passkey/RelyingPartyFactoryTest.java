package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pointbluetech.nam.login.passkey.logging.CapturingSink;
import com.pointbluetech.nam.login.passkey.logging.NidpLoggerFactory;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.UserIdentity;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RelyingPartyFactoryTest {

    /** Repository with no users; enough to exercise option generation. */
    static final CredentialRepository EMPTY = new CredentialRepository() {
        @Override
        public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
            return Collections.emptySet();
        }

        @Override
        public Optional<ByteArray> getUserHandleForUsername(String username) {
            return Optional.empty();
        }

        @Override
        public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
            return Optional.empty();
        }

        @Override
        public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
            return Optional.empty();
        }

        @Override
        public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
            return Collections.emptySet();
        }
    };

    private CapturingSink sink;

    @BeforeEach
    void captureLogs() {
        // Keeps the library's logging away from NIDPLog, which isn't initialized outside NAM
        sink = new CapturingSink(Level.FINE);
        NidpLoggerFactory.setSink(sink);
    }

    @AfterEach
    void restoreSink() {
        NidpLoggerFactory.resetSink();
    }

    @Test
    void registrationOptionsReflectConfig() throws Exception {
        PasskeyConfig config = PasskeyConfig.from(PasskeyConfigTest.minimal());
        RelyingParty rp = RelyingPartyFactory.create(config, EMPTY);

        String json = rp.startRegistration(StartRegistrationOptions.builder()
                        .user(UserIdentity.builder()
                                .name("alice")
                                .displayName("Alice")
                                .id(new ByteArray("guid-1234".getBytes(StandardCharsets.UTF_8)))
                                .build())
                        .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                                .residentKey(config.residentKey())
                                .userVerification(config.userVerification())
                                .build())
                        .timeout(config.timeoutMs())
                        .build())
                .toCredentialsCreateJson();

        assertTrue(json.contains("\"id\":\"example.com\""), json);
        assertTrue(json.contains("\"residentKey\":\"required\""), json);
        assertTrue(json.contains("\"attestation\":\"none\""), json);
    }

    @Test
    void usernamelessAssertionHasNoAllowCredentials() throws Exception {
        PasskeyConfig config = PasskeyConfig.from(PasskeyConfigTest.minimal());
        RelyingParty rp = RelyingPartyFactory.create(config, EMPTY);

        String json = rp.startAssertion(StartAssertionOptions.builder()
                        .userVerification(config.userVerification())
                        .timeout(config.timeoutMs())
                        .build())
                .toCredentialsGetJson();

        assertTrue(json.contains("\"rpId\":\"example.com\""), json);
        assertTrue(!json.contains("allowCredentials") || json.contains("\"allowCredentials\":[]"), json);
    }

    @Test
    void identityUsesConfiguredName() {
        Properties props = PasskeyConfigTest.minimal();
        props.setProperty("RP_NAME", "Point Blue");

        assertEquals("Point Blue", RelyingPartyFactory.identity(PasskeyConfig.from(props)).getName());
    }
}
