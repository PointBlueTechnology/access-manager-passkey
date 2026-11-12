package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserVerificationRequirement;
import java.util.Properties;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PasskeyConfigTest {

    private static final String PEPPER = "0123456789abcdef0123456789abcdef";

    static Properties minimal() {
        Properties props = new Properties();
        props.setProperty("RP_ID", "example.com");
        props.setProperty("ORIGINS", "https://login.example.com");
        return props;
    }

    @Test
    void defaultsForMinimalConfig() {
        PasskeyConfig config = PasskeyConfig.from(minimal());

        assertEquals(PasskeyConfig.Mode.MFA, config.mode());
        assertEquals("Access Manager", config.rpName());
        assertEquals(Set.of("https://login.example.com"), config.origins());
        assertEquals(UserVerificationRequirement.PREFERRED, config.userVerification());
        assertEquals(ResidentKeyRequirement.REQUIRED, config.residentKey());
        assertFalse(config.authenticatorAttachment().isPresent());
        assertEquals(120_000, config.timeoutMs());
        assertEquals(10, config.maxPasskeys());
        assertEquals("carLicense", config.passkeyAttribute());
        assertEquals("", config.auxClass());
        assertTrue(config.enrollIfNone());
        assertFalse(config.requireOne());
        assertEquals(300, config.manageMaxAuthAgeSec());
    }

    @Test
    void emailNotificationsAreOffUnlessTurnedOn() {
        PasskeyConfig defaults = PasskeyConfig.from(minimal());
        assertEquals(false, defaults.notifyEmail());
        assertEquals("mail", defaults.notifyMailAttribute());

        Properties props = minimal();
        props.setProperty("NOTIFY_EMAIL", "true");
        props.setProperty("NOTIFY_MAIL_ATTRIBUTE", "workEmail");
        PasskeyConfig on = PasskeyConfig.from(props);
        assertEquals(true, on.notifyEmail());
        assertEquals("workEmail", on.notifyMailAttribute());
    }

    @Test
    void passwordManagerSignalsAreOffUnlessTurnedOn() {
        assertFalse(PasskeyConfig.from(minimal()).signalPasswordManagers());
        assertFalse(PasskeyConfig.from(minimal()).describe().contains("signalPasswordManagers"));

        Properties props = minimal();
        props.setProperty("SIGNAL_PASSWORD_MANAGERS", "true");
        PasskeyConfig on = PasskeyConfig.from(props);
        assertTrue(on.signalPasswordManagers());
        assertTrue(on.describe().contains("signalPasswordManagers=true"));
    }

    @Test
    void accountCheckReadsTheAttributesUnlessToldOtherwise() {
        Properties props = minimal();
        props.setProperty("MODE", "LOGIN");
        PasskeyConfig defaults = PasskeyConfig.from(props);
        assertEquals(PasskeyConfig.AccountCheck.ATTRIBUTES, defaults.accountCheck());
        assertFalse(defaults.describe().contains("accountCheck"));

        props.setProperty("ACCOUNT_CHECK", "verify-rights");
        PasskeyConfig verify = PasskeyConfig.from(props);
        assertEquals(PasskeyConfig.AccountCheck.VERIFY_RIGHTS, verify.accountCheck());
        assertTrue(verify.describe().contains("accountCheck=verify-rights"));

        props.setProperty("ACCOUNT_CHECK", "off");
        assertEquals(PasskeyConfig.AccountCheck.OFF, PasskeyConfig.from(props).accountCheck());

        props.setProperty("ACCOUNT_CHECK", "sometimes");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props))
                .getMessage().contains("ACCOUNT_CHECK must be one of"));
    }

    @Test
    void recoveryCooldownIsOffUnlessSetAndHasALimit() {
        assertEquals(0, PasskeyConfig.from(minimal()).recoveryCooldownSec());

        Properties props = minimal();
        props.setProperty("RECOVERY_COOLDOWN_SEC", "86400");
        assertEquals(86_400, PasskeyConfig.from(props).recoveryCooldownSec());

        props.setProperty("RECOVERY_COOLDOWN_SEC", "2592001");
        assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props));
    }

    @Test
    void loginModeDefaultsToRequiredUserVerification() {
        Properties props = minimal();
        props.setProperty("MODE", "login");

        assertEquals(UserVerificationRequirement.REQUIRED, PasskeyConfig.from(props).userVerification());
    }

    @Test
    void loginModeRejectsWeakerUserVerification() {
        Properties props = minimal();
        props.setProperty("MODE", "LOGIN");
        props.setProperty("USER_VERIFICATION", "preferred");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props));
        assertTrue(e.getMessage().contains("USER_VERIFICATION must be required"));
    }

    @Test
    void loginModeNeedsAtLeastOneEntryStyle() {
        Properties props = minimal();
        props.setProperty("MODE", "LOGIN");
        props.setProperty("ALLOW_USERNAMELESS", "false");
        props.setProperty("ALLOW_IDENTIFIER_FIRST", "false");

        assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props));
    }

    @Test
    void acceptsWebAuthnSpellingOfEnumValues() {
        Properties props = minimal();
        props.setProperty("AUTHENTICATOR_ATTACHMENT", "cross-platform");

        assertEquals(AuthenticatorAttachment.CROSS_PLATFORM, PasskeyConfig.from(props).authenticatorAttachment().get());
    }

    @Test
    void upgradeModeNeedsNothingMore() {
        Properties props = minimal();
        props.setProperty("MODE", "upgrade");

        PasskeyConfig config = PasskeyConfig.from(props);
        assertEquals(PasskeyConfig.Mode.UPGRADE, config.mode());
        assertEquals("passkey_upgrade", config.upgradeJsp());
    }

    @Test
    void upgradeModeRefusesWhatABrowserCreatedPasskeyCannotSatisfy() {
        String[][] cases = {
                {"ENROLL_GATES", "email", "ENROLL_GATES can't be used in UPGRADE mode"},
                {"ALLOWED_AAGUIDS", "ee882879-721c-4913-9775-3dfcce97072a", "ALLOWED_AAGUIDS can't be used in UPGRADE mode"},
                {"AUTHENTICATOR_ATTACHMENT", "cross-platform", "can't be cross-platform in UPGRADE mode"},
        };
        for (String[] c : cases) {
            Properties props = minimal();
            props.setProperty("MODE", "UPGRADE");
            props.setProperty(c[0], c[1]);

            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props));
            assertTrue(e.getMessage().contains(c[2]), e.getMessage());
        }
    }

    @Test
    void reportsAllProblemsAtOnce() {
        Properties props = new Properties();
        props.setProperty("MODE", "sideways");
        props.setProperty("TIMEOUT_MS", "soon");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props));
        assertTrue(e.getMessage().contains("MODE must be one of"));
        assertTrue(e.getMessage().contains("RP_ID is required"));
        assertTrue(e.getMessage().contains("ORIGINS is required"));
        assertTrue(e.getMessage().contains("TIMEOUT_MS must be a number"));
    }

    @Test
    void parsesMultipleOriginsAndNormalizesCase() {
        Properties props = minimal();
        props.setProperty("ORIGINS", " https://Login.Example.com , https://idp2.example.com:8443 ");

        assertEquals(Set.of("https://login.example.com", "https://idp2.example.com:8443"),
                PasskeyConfig.from(props).origins());
    }

    @Test
    void rejectsOriginsOffTheRpIdOrNotHttps() {
        for (String bad : new String[] {
                "http://login.example.com",
                "https://login.example.org",
                "https://evilexample.com",
                "https://login.example.com/nidp",
        }) {
            Properties props = minimal();
            props.setProperty("ORIGINS", bad);
            assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props), bad);
        }
    }

    @Test
    void rejectsIpAddressRpId() {
        Properties props = new Properties();
        props.setProperty("RP_ID", "192.168.201.90");
        props.setProperty("ORIGINS", "https://192.168.201.90:2443");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props));
        assertTrue(e.getMessage().contains("RP_ID must be a DNS name"));
    }

    @Test
    void storageAttributeAndAuxClassAreConfigurable() {
        Properties props = minimal();
        props.setProperty("PASSKEY_LDAP_ATTRIBUTE", "pbtPasskeyCredential");
        props.setProperty("PASSKEY_AUX_CLASS", "pbtPasskeyUser");

        PasskeyConfig config = PasskeyConfig.from(props);
        assertEquals("pbtPasskeyCredential", config.passkeyAttribute());
        assertEquals("pbtPasskeyUser", config.auxClass());

        props.setProperty("PASSKEY_AUX_CLASS", "none");
        assertEquals("", PasskeyConfig.from(props).auxClass());
    }

    @Test
    void passkeyOnlyHidesAFallbackSetOnTheClass() {
        Properties props = minimal();
        props.setProperty("FALLBACK_CONTRACT_URL", "/nidp/app/login?id=Password");
        assertEquals("/nidp/app/login?id=Password", PasskeyConfig.from(props).fallbackContractUrl());

        props.setProperty("PASSKEY_ONLY", "true");
        assertEquals("", PasskeyConfig.from(props).fallbackContractUrl());
    }

    @Test
    void onlyThePasswordlessPageFallsBackToNamsDefaultContract() {
        Properties props = minimal();
        assertTrue(PasskeyConfig.from(props).describe().contains("fallback=none"), "MFA mode has no default fallback");

        props.setProperty("MODE", "LOGIN");
        assertTrue(PasskeyConfig.from(props).describe().contains("fallback=NAM's default contract"));

        props.setProperty("PASSKEY_ONLY", "true");
        assertTrue(PasskeyConfig.from(props).describe().contains("fallback=none"));
        assertTrue(PasskeyConfig.from(props).describe().contains("passkeyOnly=true"));

        props.setProperty("PASSKEY_ONLY", "false");
        props.setProperty("FALLBACK_CONTRACT_URL", "/nidp/app/login?id=Password");
        assertTrue(PasskeyConfig.from(props).describe().contains("fallback=/nidp/app/login?id=Password"));
    }

    @Test
    void recoveryAttributesDefaultToThePasskeyAttribute() {
        PasskeyConfig config = PasskeyConfig.from(minimal());
        assertEquals("carLicense", config.recoveryAttribute());
        assertEquals("carLicense", config.tokenAttribute());

        Properties props = minimal();
        props.setProperty("PASSKEY_LDAP_ATTRIBUTE", "pbtPasskeyCredential");
        props.setProperty("PASSKEY_ENROLL_TOKEN_ATTRIBUTE", "pbtPasskeyEnrollToken");
        config = PasskeyConfig.from(props);
        assertEquals("pbtPasskeyCredential", config.recoveryAttribute());
        assertEquals("pbtPasskeyEnrollToken", config.tokenAttribute());
    }

    @Test
    void shortPepperIsRejectedWithoutPuttingItInTheMessage() {
        Properties props = minimal();
        props.setProperty("RECOVERY_PEPPER", "tooshort");

        String message = assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props)).getMessage();
        assertTrue(message.contains("RECOVERY_PEPPER must be at least 32 characters"));
        assertFalse(message.contains("tooshort"));
    }

    @Test
    void pepperIsOptionalOutsideRecoveryAndNeverDescribed() {
        assertFalse(PasskeyConfig.from(minimal()).recoveryPepper().isPresent());

        Properties props = minimal();
        props.setProperty("RECOVERY_PEPPER", PEPPER);
        PasskeyConfig config = PasskeyConfig.from(props);
        assertTrue(config.recoveryPepper().isPresent());
        assertFalse(config.describe().contains(PEPPER));
    }

    @Test
    void recoveryAndHelpdeskNeedTheirSettings() {
        Properties props = minimal();
        props.setProperty("MODE", "RECOVERY");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props))
                .getMessage().contains("RECOVERY_PEPPER is required"));

        props.setProperty("MODE", "HELPDESK");
        props.setProperty("RECOVERY_PEPPER", PEPPER);
        assertTrue(assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props))
                .getMessage().contains("HELPDESK_GROUP_DN is required"));

        props.setProperty("HELPDESK_GROUP_DN", "cn=helpdesk,o=novell");
        assertEquals(PasskeyConfig.Mode.HELPDESK, PasskeyConfig.from(props).mode());
    }

    @Test
    void helpdeskAllowedDnsMatchIgnoringCaseAndSpacing() {
        Properties props = minimal();
        assertFalse(PasskeyConfig.from(props).isHelpdeskAllowedDn("cn=admin,o=novell"), "nobody by default");
        assertFalse(PasskeyConfig.from(props).isHelpdeskAllowedDn(""));

        props.setProperty("HELPDESK_ALLOWED_DNS", "cn=admin,o=novell; cn=ops,o=novell");
        PasskeyConfig config = PasskeyConfig.from(props);

        assertTrue(config.isHelpdeskAllowedDn("CN=Admin, O=Novell"));
        assertTrue(config.isHelpdeskAllowedDn("cn=ops,o=novell"));
        assertFalse(config.isHelpdeskAllowedDn("cn=admin2,o=novell"));
        assertFalse(config.isHelpdeskAllowedDn("o=novell"));
        assertFalse(config.isHelpdeskAllowedDn(null));
    }

    @Test
    void rejectsOutOfRangeNumbers() {
        Properties props = minimal();
        props.setProperty("MAX_PASSKEYS", "0");

        assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props));
    }

    @Test
    void enrollmentGatesAreParsedInOrderAndChecked() {
        assertTrue(PasskeyConfig.from(minimal()).enrollGates().isEmpty(), "password only by default");

        Properties props = minimal();
        props.setProperty("ENROLL_GATES", " Helpdesk , email,email ");
        props.setProperty("RECOVERY_PEPPER", PEPPER);
        assertEquals(java.util.List.of(PasskeyConfig.EnrollGate.HELPDESK, PasskeyConfig.EnrollGate.EMAIL),
                PasskeyConfig.from(props).enrollGates());

        props.remove("RECOVERY_PEPPER");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props))
                .getMessage().contains("RECOVERY_PEPPER is required for the helpdesk enrollment gate"));

        props.setProperty("ENROLL_GATES", "fingerprint");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props))
                .getMessage().contains("ENROLL_GATES values must be"));
    }

    @Test
    void allowListNeedsTrustedRootsAndAttestation() throws Exception {
        PasskeyConfig open = PasskeyConfig.from(minimal());
        assertTrue(open.allowedAaguids().isEmpty());
        assertEquals(com.yubico.webauthn.data.AttestationConveyancePreference.NONE, open.attestation());

        Properties props = minimal();
        props.setProperty("ALLOWED_AAGUIDS", "EE882879-721C-4913-9775-3DFCCE97072A, cb69481e8ff7403993ec0a2729a154a8");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props))
                .getMessage().contains("ATTESTATION_TRUST_ROOTS is required"));

        props.setProperty("ATTESTATION_TRUST_ROOTS", new TestAttestation("Vendor").rootPem());
        PasskeyConfig config = PasskeyConfig.from(props);
        assertEquals(Set.of("ee882879721c491397753dfcce97072a", "cb69481e8ff7403993ec0a2729a154a8"),
                config.allowedAaguids());
        assertEquals(1, config.attestationTrustRoots().size());
        assertEquals(com.yubico.webauthn.data.AttestationConveyancePreference.DIRECT, config.attestation(),
                "asks for attestation by default");

        props.setProperty("ATTESTATION", "none");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props))
                .getMessage().contains("ATTESTATION must be direct or enterprise"));
    }

    @Test
    void allowListRejectsBadValues() {
        Properties props = minimal();
        props.setProperty("ALLOWED_AAGUIDS", "00000000-0000-0000-0000-000000000000, not-an-aaguid");
        props.setProperty("ATTESTATION_TRUST_ROOTS", "-----BEGIN CERTIFICATE-----bm90IGEgY2VydA==-----END CERTIFICATE-----");
        String message = assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props)).getMessage();
        assertTrue(message.contains("all-zero AAGUID"), message);
        assertTrue(message.contains("got 'not-an-aaguid'"), message);
        assertTrue(message.contains("certificate 1 can't be read"), message);
    }

    @Test
    void securityQuestionsReadSsprAnswersByDefault() {
        Properties props = minimal();
        props.setProperty("ENROLL_GATES", "email,questions");
        PasskeyConfig config = PasskeyConfig.from(props);
        assertEquals(java.util.List.of(PasskeyConfig.EnrollGate.EMAIL, PasskeyConfig.EnrollGate.QUESTIONS), config.enrollGates());
        assertEquals(PasskeyConfig.QuestionStore.SSPR, config.questionStore());
        assertEquals("pwmResponseSet", config.questionsSsprAttribute());

        props.setProperty("QUESTIONS_SSPR_ATTRIBUTE", "pbtResponses");
        assertEquals("pbtResponses", PasskeyConfig.from(props).questionsSsprAttribute());
    }

    @Test
    void securityQuestionsCanUseAnNmasLogin() {
        Properties props = minimal();
        props.setProperty("ENROLL_GATES", "questions");
        props.setProperty("QUESTIONS_STORE", "nmas");
        PasskeyConfig config = PasskeyConfig.from(props);
        assertEquals(PasskeyConfig.QuestionStore.NMAS, config.questionStore());
        assertEquals("Challenge Response", config.questionsNmasSequence());
        assertEquals(180, config.questionsNmasTimeoutSec());
        assertTrue(config.describe().contains("questions=nmas 'Challenge Response'"));

        props.setProperty("QUESTIONS_NMAS_SEQUENCE", "Site Questions");
        props.setProperty("QUESTIONS_NMAS_TIMEOUT_SEC", "300");
        config = PasskeyConfig.from(props);
        assertEquals("Site Questions", config.questionsNmasSequence());
        assertEquals(300, config.questionsNmasTimeoutSec());

        props.setProperty("QUESTIONS_NMAS_TIMEOUT_SEC", "5");
        assertThrows(IllegalArgumentException.class, () -> PasskeyConfig.from(props));
    }
}
