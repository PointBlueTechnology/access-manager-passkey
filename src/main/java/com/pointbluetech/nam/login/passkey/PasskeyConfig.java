package com.pointbluetech.nam.login.passkey;

import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserVerificationRequirement;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Immutable view of the class/method properties configured in Administration Console.
 *
 * {@link #from(Properties)} validates everything up front and reports all problems at once, so
 * a misconfigured method fails when the Identity Server loads it rather than mid-login.
 * Properties for later phases (recovery, helpdesk) are added alongside those features.
 */
public final class PasskeyConfig {

    public enum Mode { MFA, LOGIN, MANAGE, RECOVERY, HELPDESK }

    /** Extra checks before a user's first passkey, in the order they're asked for. */
    public enum EnrollGate { EMAIL, HELPDESK, QUESTIONS }

    /** Where users' challenge-response answers are kept. */
    public enum QuestionStore { SSPR, NMAS }

    /** 64 hex characters from {@code openssl rand -hex 32} is the intended value. */
    static final int MIN_PEPPER_LENGTH = 32;

    public static final String MODE = "MODE";
    public static final String RP_ID = "RP_ID";
    public static final String RP_NAME = "RP_NAME";
    public static final String ORIGINS = "ORIGINS";
    public static final String USER_VERIFICATION = "USER_VERIFICATION";
    public static final String RESIDENT_KEY = "RESIDENT_KEY";
    public static final String AUTHENTICATOR_ATTACHMENT = "AUTHENTICATOR_ATTACHMENT";
    public static final String ATTESTATION = "ATTESTATION";
    public static final String ALLOWED_AAGUIDS = "ALLOWED_AAGUIDS";
    public static final String ATTESTATION_TRUST_ROOTS = "ATTESTATION_TRUST_ROOTS";
    public static final String TIMEOUT_MS = "TIMEOUT_MS";
    public static final String CHALLENGE_TTL_SEC = "CHALLENGE_TTL_SEC";
    public static final String ALLOW_USERNAMELESS = "ALLOW_USERNAMELESS";
    public static final String ALLOW_IDENTIFIER_FIRST = "ALLOW_IDENTIFIER_FIRST";
    public static final String ENROLL_IF_NONE = "ENROLL_IF_NONE";
    public static final String MAX_PASSKEYS = "MAX_PASSKEYS";
    public static final String PASSKEY_LDAP_ATTRIBUTE = "PASSKEY_LDAP_ATTRIBUTE";
    public static final String PASSKEY_AUX_CLASS = "PASSKEY_AUX_CLASS";
    public static final String FALLBACK_CONTRACT_URL = "FALLBACK_CONTRACT_URL";
    public static final String LAST_USED_WRITE_INTERVAL = "LAST_USED_WRITE_INTERVAL";
    public static final String JSP_MFA = "JSP_MFA";
    public static final String JSP_REGISTER = "JSP_REGISTER";
    public static final String JSP_MANAGE = "JSP_MANAGE";
    public static final String JSP_LOGIN = "JSP_LOGIN";
    public static final String JSP_RECOVERY = "JSP_RECOVERY";
    public static final String JSP_GATE = "JSP_GATE";
    public static final String JSP_CODES = "JSP_CODES";
    public static final String JSP_HELPDESK = "JSP_HELPDESK";
    public static final String PASSKEY_ONLY = "PASSKEY_ONLY";
    public static final String RECOVERY_URL = "RECOVERY_URL";
    public static final String PASSKEY_RECOVERY_ATTRIBUTE = "PASSKEY_RECOVERY_ATTRIBUTE";
    public static final String PASSKEY_ENROLL_TOKEN_ATTRIBUTE = "PASSKEY_ENROLL_TOKEN_ATTRIBUTE";
    public static final String RECOVERY_PEPPER = "RECOVERY_PEPPER";
    public static final String RECOVERY_CODE_COUNT = "RECOVERY_CODE_COUNT";
    public static final String MAX_FAILED = "MAX_FAILED";
    public static final String HELPDESK_GROUP_DN = "HELPDESK_GROUP_DN";
    public static final String HELPDESK_ALLOWED_DNS = "HELPDESK_ALLOWED_DNS";
    public static final String ENROLL_TOKEN_TTL_SEC = "ENROLL_TOKEN_TTL_SEC";
    public static final String REQUIRE_ONE = "REQUIRE_ONE";
    public static final String MANAGE_MAX_AUTH_AGE_SEC = "MANAGE_MAX_AUTH_AGE_SEC";
    /** Email the user about changes to their passkeys, through NAM's own email configuration */
    public static final String RECOVERY_COOLDOWN_SEC = "RECOVERY_COOLDOWN_SEC";
    public static final String ENROLL_GATES = "ENROLL_GATES";
    public static final String QUESTIONS_STORE = "QUESTIONS_STORE";
    public static final String QUESTIONS_SSPR_ATTRIBUTE = "QUESTIONS_SSPR_ATTRIBUTE";
    public static final String QUESTIONS_NMAS_SEQUENCE = "QUESTIONS_NMAS_SEQUENCE";
    public static final String QUESTIONS_NMAS_TIMEOUT_SEC = "QUESTIONS_NMAS_TIMEOUT_SEC";
    public static final String NOTIFY_EMAIL = "NOTIFY_EMAIL";
    public static final String NOTIFY_MAIL_ATTRIBUTE = "NOTIFY_MAIL_ATTRIBUTE";

    private final Mode mode;
    private final String rpId;
    private final String rpName;
    private final Set<String> origins;
    private final UserVerificationRequirement userVerification;
    private final ResidentKeyRequirement residentKey;
    private final AuthenticatorAttachment authenticatorAttachment;
    private final AttestationConveyancePreference attestation;
    private final Set<String> allowedAaguids;
    private final List<X509Certificate> attestationTrustRoots;
    private final long timeoutMs;
    private final int challengeTtlSec;
    private final boolean allowUsernameless;
    private final boolean allowIdentifierFirst;
    private final boolean enrollIfNone;
    private final int maxPasskeys;
    private final String passkeyAttribute;
    private final String auxClass;
    private final String fallbackContractUrl;
    private final long lastUsedWriteIntervalSec;
    private final String mfaJsp;
    private final String registerJsp;
    private final String manageJsp;
    private final String loginJsp;
    private final String recoveryJsp;
    private final String gateJsp;
    private final String codesJsp;
    private final String helpdeskJsp;
    private final boolean passkeyOnly;
    private final String recoveryUrl;
    private final String recoveryAttribute;
    private final String tokenAttribute;
    private final byte[] recoveryPepper;
    private final int recoveryCodeCount;
    private final int maxFailed;
    private final String helpdeskGroupDn;
    private final List<String> helpdeskAllowedDns;
    private final long enrollTokenTtlSec;
    private final boolean requireOne;
    private final int manageMaxAuthAgeSec;
    private final long recoveryCooldownSec;
    private final List<EnrollGate> enrollGates;
    private final QuestionStore questionStore;
    private final String questionsSsprAttribute;
    private final String questionsNmasSequence;
    private final int questionsNmasTimeoutSec;
    private final boolean notifyEmail;
    private final String notifyMailAttribute;

    private PasskeyConfig(Parser p) {
        mode = p.enumValue(MODE, Mode.class, Mode.MFA);
        rpId = p.required(RP_ID);
        rpName = p.string(RP_NAME, "Access Manager");
        origins = p.origins(rpId);
        // A passkey used on its own must prove the user (PIN/biometric); as a second factor it may not
        userVerification = p.enumValue(USER_VERIFICATION, UserVerificationRequirement.class,
                mode == Mode.MFA ? UserVerificationRequirement.PREFERRED : UserVerificationRequirement.REQUIRED);
        residentKey = p.enumValue(RESIDENT_KEY, ResidentKeyRequirement.class, ResidentKeyRequirement.REQUIRED);
        authenticatorAttachment = p.enumValue(AUTHENTICATOR_ATTACHMENT, AuthenticatorAttachment.class, null);
        allowedAaguids = aaguids(p, p.string(ALLOWED_AAGUIDS, ""));
        attestationTrustRoots = certificates(p, p.string(ATTESTATION_TRUST_ROOTS, ""));
        AttestationConveyancePreference requested =
                p.enumValue(ATTESTATION, AttestationConveyancePreference.class, AttestationConveyancePreference.NONE);
        if (!allowedAaguids.isEmpty()) {
            // The AAGUID is only worth checking when a trusted attestation vouches for it
            if (attestationTrustRoots.isEmpty()) {
                p.error(ATTESTATION_TRUST_ROOTS + " is required with " + ALLOWED_AAGUIDS
                        + ": without trusted roots, any software can claim an allowed AAGUID");
            }
            if (p.string(ATTESTATION, "").isEmpty()) {
                requested = AttestationConveyancePreference.DIRECT;
            } else if (requested == AttestationConveyancePreference.NONE) {
                p.error(ATTESTATION + " must be direct or enterprise with " + ALLOWED_AAGUIDS);
            }
        }
        attestation = requested;
        timeoutMs = p.integer(TIMEOUT_MS, 120_000, 10_000, 600_000);
        challengeTtlSec = (int) p.integer(CHALLENGE_TTL_SEC, 300, 30, 3_600);
        allowUsernameless = p.bool(ALLOW_USERNAMELESS, true);
        allowIdentifierFirst = p.bool(ALLOW_IDENTIFIER_FIRST, true);
        enrollIfNone = p.bool(ENROLL_IF_NONE, true);
        maxPasskeys = (int) p.integer(MAX_PASSKEYS, 10, 1, 50);
        passkeyAttribute = p.string(PASSKEY_LDAP_ATTRIBUTE, "carLicense");
        auxClass = p.auxClass(PASSKEY_AUX_CLASS);
        fallbackContractUrl = p.string(FALLBACK_CONTRACT_URL, "");
        lastUsedWriteIntervalSec = p.integer(LAST_USED_WRITE_INTERVAL, 86_400, 0, 31_536_000);
        mfaJsp = p.string(JSP_MFA, "passkey_mfa");
        registerJsp = p.string(JSP_REGISTER, "passkey_register");
        manageJsp = p.string(JSP_MANAGE, "passkey_manage");
        loginJsp = p.string(JSP_LOGIN, "passkey_login");
        recoveryJsp = p.string(JSP_RECOVERY, "passkey_recovery");
        gateJsp = p.string(JSP_GATE, "passkey_gate");
        codesJsp = p.string(JSP_CODES, "passkey_codes");
        helpdeskJsp = p.string(JSP_HELPDESK, "passkey_helpdesk");
        passkeyOnly = p.bool(PASSKEY_ONLY, false);
        recoveryUrl = p.string(RECOVERY_URL, "");
        // Sharing the passkey attribute works because every kind of value has its own prefix
        recoveryAttribute = p.string(PASSKEY_RECOVERY_ATTRIBUTE, passkeyAttribute);
        tokenAttribute = p.string(PASSKEY_ENROLL_TOKEN_ATTRIBUTE, passkeyAttribute);
        String pepper = p.string(RECOVERY_PEPPER, "");
        recoveryPepper = pepper.getBytes(StandardCharsets.UTF_8);
        recoveryCodeCount = (int) p.integer(RECOVERY_CODE_COUNT, 10, 1, 50);
        maxFailed = (int) p.integer(MAX_FAILED, 5, 1, 100);
        helpdeskGroupDn = p.string(HELPDESK_GROUP_DN, "");
        // Semicolons, because the DNs themselves contain commas
        helpdeskAllowedDns = Collections.unmodifiableList(Arrays.asList(p.string(HELPDESK_ALLOWED_DNS, "").split(";")));
        enrollTokenTtlSec = p.integer(ENROLL_TOKEN_TTL_SEC, 86_400, 300, 604_800);

        if ((mode == Mode.RECOVERY || mode == Mode.HELPDESK) && pepper.isEmpty()) {
            p.error(RECOVERY_PEPPER + " is required in " + mode + " mode");
        }
        if (!pepper.isEmpty() && pepper.length() < MIN_PEPPER_LENGTH) {
            // Reports the length only: this message goes to the log
            p.error(RECOVERY_PEPPER + " must be at least " + MIN_PEPPER_LENGTH + " characters, was " + pepper.length());
        }
        if (mode == Mode.HELPDESK && helpdeskGroupDn.isEmpty()) {
            p.error(HELPDESK_GROUP_DN + " is required in HELPDESK mode");
        }
        requireOne = p.bool(REQUIRE_ONE, false);
        manageMaxAuthAgeSec = (int) p.integer(MANAGE_MAX_AUTH_AGE_SEC, 300, 30, 86_400);
        recoveryCooldownSec = p.integer(RECOVERY_COOLDOWN_SEC, 0, 0, 2_592_000);
        enrollGates = enrollGates(p, p.string(ENROLL_GATES, ""));
        questionStore = p.enumValue(QUESTIONS_STORE, QuestionStore.class, QuestionStore.SSPR);
        questionsSsprAttribute = p.string(QUESTIONS_SSPR_ATTRIBUTE, "pwmResponseSet");
        questionsNmasSequence = p.string(QUESTIONS_NMAS_SEQUENCE, "Challenge Response");
        questionsNmasTimeoutSec = (int) p.integer(QUESTIONS_NMAS_TIMEOUT_SEC, 180, 30, 900);
        if (enrollGates.contains(EnrollGate.HELPDESK) && pepper.isEmpty()) {
            p.error(RECOVERY_PEPPER + " is required for the helpdesk enrollment gate");
        }
        notifyEmail = p.bool(NOTIFY_EMAIL, false);
        notifyMailAttribute = p.string(NOTIFY_MAIL_ATTRIBUTE, "mail");

        if (mode == Mode.LOGIN) {
            if (!allowUsernameless && !allowIdentifierFirst) {
                p.error(ALLOW_USERNAMELESS + " and " + ALLOW_IDENTIFIER_FIRST + " cannot both be false in LOGIN mode");
            }
            if (userVerification != UserVerificationRequirement.REQUIRED) {
                p.error(USER_VERIFICATION + " must be required in LOGIN mode (the passkey is the only factor)");
            }
        }
        if (passkeyAttribute.isEmpty()) {
            p.error(PASSKEY_LDAP_ATTRIBUTE + " must not be blank");
        }
        if (isIpLiteral(rpId)) {
            // Browsers reject IP addresses as RP IDs; the IDP base URL needs a DNS name
            p.error(RP_ID + " must be a DNS name, not an IP address ('" + rpId + "')");
        }
    }

    private static Set<String> aaguids(Parser p, String value) {
        Set<String> found = new LinkedHashSet<>();
        for (String part : value.split("[,;\\s]+")) {
            String hex = part.replace("-", "").toLowerCase(Locale.ROOT);
            if (hex.isEmpty()) {
                continue;
            }
            if (!hex.matches("[0-9a-f]{32}")) {
                p.error(ALLOWED_AAGUIDS + " values must be AAGUIDs such as ee882879-721c-4913-9775-3dfcce97072a; got '"
                        + part + "'");
            } else if (hex.equals("00000000000000000000000000000000")) {
                p.error(ALLOWED_AAGUIDS + " can't include the all-zero AAGUID, which any authenticator may report");
            } else {
                found.add(hex);
            }
        }
        return Collections.unmodifiableSet(found);
    }

    /**
     * PEM certificates. Administration Console fields are one line, so the line breaks inside a
     * certificate are optional.
     */
    private static List<X509Certificate> certificates(Parser p, String value) {
        List<X509Certificate> certificates = new ArrayList<>();
        Matcher pem = Pattern.compile("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL)
                .matcher(value);
        int found = 0;
        while (pem.find()) {
            found++;
            try {
                byte[] der = Base64.getDecoder().decode(pem.group(1).replaceAll("\\s", ""));
                certificates.add((X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(der)));
            } catch (IllegalArgumentException | CertificateException e) {
                p.error(ATTESTATION_TRUST_ROOTS + " certificate " + found + " can't be read: " + e.getMessage());
            }
        }
        if (found == 0 && !value.trim().isEmpty()) {
            p.error(ATTESTATION_TRUST_ROOTS + " must hold PEM certificates (-----BEGIN CERTIFICATE----- ...)");
        }
        return Collections.unmodifiableList(certificates);
    }

    private static List<EnrollGate> enrollGates(Parser p, String value) {
        Set<EnrollGate> gates = new LinkedHashSet<>();
        for (String part : value.split(",")) {
            String name = part.trim();
            if (name.isEmpty()) {
                continue;
            }
            try {
                gates.add(EnrollGate.valueOf(name.toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException e) {
                p.error(ENROLL_GATES + " values must be email, helpdesk or questions, separated by commas; got '" + name + "'");
            }
        }
        return Collections.unmodifiableList(new ArrayList<>(gates));
    }

    /** @throws IllegalArgumentException listing every invalid or missing property */
    public static PasskeyConfig from(Properties props) {
        Parser parser = new Parser(props);
        PasskeyConfig config = new PasskeyConfig(parser);
        parser.throwIfErrors();
        return config;
    }

    public Mode mode() { return mode; }
    public String rpId() { return rpId; }
    public String rpName() { return rpName; }
    public Set<String> origins() { return origins; }
    public UserVerificationRequirement userVerification() { return userVerification; }
    public ResidentKeyRequirement residentKey() { return residentKey; }
    public Optional<AuthenticatorAttachment> authenticatorAttachment() { return Optional.ofNullable(authenticatorAttachment); }
    public AttestationConveyancePreference attestation() { return attestation; }
    /** Lower-case hex AAGUIDs without dashes; empty means any authenticator. */
    public Set<String> allowedAaguids() { return allowedAaguids; }
    public List<X509Certificate> attestationTrustRoots() { return attestationTrustRoots; }
    public long timeoutMs() { return timeoutMs; }
    public int challengeTtlSec() { return challengeTtlSec; }
    public boolean allowUsernameless() { return allowUsernameless; }
    public boolean allowIdentifierFirst() { return allowIdentifierFirst; }
    public boolean enrollIfNone() { return enrollIfNone; }
    public int maxPasskeys() { return maxPasskeys; }
    public String passkeyAttribute() { return passkeyAttribute; }
    public String auxClass() { return auxClass; }
    /** Empty on a passkey-only method, whatever the class says: that's what the option is for. */
    public String fallbackContractUrl() { return passkeyOnly ? "" : fallbackContractUrl; }
    public long lastUsedWriteIntervalSec() { return lastUsedWriteIntervalSec; }
    public String mfaJsp() { return mfaJsp; }
    public String registerJsp() { return registerJsp; }
    public String manageJsp() { return manageJsp; }
    public String loginJsp() { return loginJsp; }
    public String recoveryJsp() { return recoveryJsp; }
    public String gateJsp() { return gateJsp; }
    public String codesJsp() { return codesJsp; }
    public String helpdeskJsp() { return helpdeskJsp; }
    public boolean passkeyOnly() { return passkeyOnly; }
    public String recoveryUrl() { return recoveryUrl; }
    public String recoveryAttribute() { return recoveryAttribute; }
    public String tokenAttribute() { return tokenAttribute; }
    /** The key for hashing recovery codes and tokens, if set. Never log it. */
    public Optional<byte[]> recoveryPepper() {
        return recoveryPepper.length == 0 ? Optional.empty() : Optional.of(recoveryPepper.clone());
    }
    public int recoveryCodeCount() { return recoveryCodeCount; }
    public int maxFailed() { return maxFailed; }
    public String helpdeskGroupDn() { return helpdeskGroupDn; }

    /** Whether this user is named directly as allowed to use helpdesk, whatever groups they're in. */
    public boolean isHelpdeskAllowedDn(String userDn) {
        String wanted = normalizeDn(userDn);
        if (wanted.isEmpty()) {
            return false;
        }
        for (String allowed : helpdeskAllowedDns) {
            if (wanted.equals(normalizeDn(allowed))) {
                return true;
            }
        }
        return false;
    }
    public long enrollTokenTtlSec() { return enrollTokenTtlSec; }

    /** Fails closed: a blank group DN matches nobody. */
    static boolean isMemberOf(List<String> memberships, String groupDn) {
        String wanted = normalizeDn(groupDn);
        if (wanted.isEmpty()) {
            return false;
        }
        for (String membership : memberships) {
            if (wanted.equals(normalizeDn(membership))) {
                return true;
            }
        }
        return false;
    }

    private static String normalizeDn(String dn) {
        return dn == null ? "" : dn.trim().toLowerCase(Locale.ROOT).replaceAll("\\s*([,=])\\s*", "$1");
    }
    public boolean requireOne() { return requireOne; }
    /** What a user must pass before their first passkey, beyond the earlier methods; empty for nothing more. */
    public List<EnrollGate> enrollGates() { return enrollGates; }
    public QuestionStore questionStore() { return questionStore; }
    public String questionsSsprAttribute() { return questionsSsprAttribute; }
    public String questionsNmasSequence() { return questionsNmasSequence; }
    public int questionsNmasTimeoutSec() { return questionsNmasTimeoutSec; }
    /** How long after a recovery new recovery codes are held back; 0 for not at all. */
    public long recoveryCooldownSec() { return recoveryCooldownSec; }
    public boolean notifyEmail() { return notifyEmail; }
    public String notifyMailAttribute() { return notifyMailAttribute; }
    public int manageMaxAuthAgeSec() { return manageMaxAuthAgeSec; }

    static boolean isIpLiteral(String host) {
        return host.matches("\\d{1,3}(\\.\\d{1,3}){3}") || host.contains(":") || host.startsWith("[");
    }

    /** One-line summary for the init log; contains no secrets. */
    public String describe() {
        return "mode=" + mode + ", rpId=" + rpId + ", origins=" + origins
                + ", userVerification=" + userVerification.getValue()
                + ", residentKey=" + residentKey.getValue()
                + ", attribute=" + passkeyAttribute
                + ", fallback=" + (!fallbackContractUrl().isEmpty() ? fallbackContractUrl()
                        : !passkeyOnly && mode == Mode.LOGIN ? "NAM's default contract" : "none")
                + (passkeyOnly ? ", passkeyOnly=true" : "")
                + (enrollGates.isEmpty() ? "" : ", enrollGates=" + enrollGates)
                + (!enrollGates.contains(EnrollGate.QUESTIONS) ? ""
                        : questionStore == QuestionStore.NMAS
                                ? ", questions=nmas '" + questionsNmasSequence + "'"
                                : ", questions=sspr " + questionsSsprAttribute)
                + (allowedAaguids.isEmpty() ? "" : ", allowedAaguids=" + allowedAaguids.size()
                        + ", trustRoots=" + attestationTrustRoots.size())
                + ", recoveryCooldownSec=" + recoveryCooldownSec
                + ", notifyEmail=" + notifyEmail;
    }

    private static final class Parser {
        private final Properties props;
        private final List<String> errors = new ArrayList<>();

        Parser(Properties props) {
            this.props = props == null ? new Properties() : props;
        }

        void error(String message) {
            errors.add(message);
        }

        void throwIfErrors() {
            if (!errors.isEmpty()) {
                throw new IllegalArgumentException("Invalid passkey configuration: " + String.join("; ", errors));
            }
        }

        private String raw(String key) {
            String value = props.getProperty(key);
            return value == null ? null : value.trim();
        }

        String string(String key, String defaultValue) {
            String value = raw(key);
            return value == null || value.isEmpty() ? defaultValue : value;
        }

        /** An attribute already on the user class, like carLicense, needs no aux class. */
        String auxClass(String key) {
            String value = string(key, "");
            return value.equalsIgnoreCase("none") ? "" : value;
        }

        String required(String key) {
            String value = raw(key);
            if (value == null || value.isEmpty()) {
                error(key + " is required");
                return "";
            }
            return value;
        }

        boolean bool(String key, boolean defaultValue) {
            String value = raw(key);
            if (value == null || value.isEmpty()) {
                return defaultValue;
            }
            if (value.equalsIgnoreCase("true")) {
                return true;
            }
            if (value.equalsIgnoreCase("false")) {
                return false;
            }
            error(key + " must be true or false, was '" + value + "'");
            return defaultValue;
        }

        long integer(String key, long defaultValue, long min, long max) {
            String value = raw(key);
            if (value == null || value.isEmpty()) {
                return defaultValue;
            }
            try {
                long parsed = Long.parseLong(value);
                if (parsed < min || parsed > max) {
                    error(key + " must be between " + min + " and " + max + ", was " + parsed);
                    return defaultValue;
                }
                return parsed;
            } catch (NumberFormatException e) {
                error(key + " must be a number, was '" + value + "'");
                return defaultValue;
            }
        }

        /** Accepts the enum constant name or the WebAuthn value, e.g. "cross-platform". */
        <E extends Enum<E>> E enumValue(String key, Class<E> type, E defaultValue) {
            String value = raw(key);
            if (value == null || value.isEmpty()) {
                return defaultValue;
            }
            String normalized = value.toUpperCase(Locale.ROOT).replace('-', '_');
            for (E constant : type.getEnumConstants()) {
                if (constant.name().equals(normalized)) {
                    return constant;
                }
            }
            List<String> allowed = new ArrayList<>();
            for (E constant : type.getEnumConstants()) {
                allowed.add(constant.name().toLowerCase(Locale.ROOT).replace('_', '-'));
            }
            error(key + " must be one of " + allowed + ", was '" + value + "'");
            return defaultValue;
        }

        /**
         * ORIGINS is required: browsers report the exact scheme://host[:port] the IDP was reached on,
         * which can't be inferred from RP_ID. Each origin must be https and on RP_ID or a subdomain.
         */
        Set<String> origins(String rpId) {
            String value = raw(ORIGINS);
            if (value == null || value.isEmpty()) {
                error(ORIGINS + " is required (comma-separated, e.g. https://login.example.com)");
                return Collections.emptySet();
            }
            Set<String> result = new LinkedHashSet<>();
            for (String part : value.split(",")) {
                String origin = part.trim();
                if (origin.isEmpty()) {
                    continue;
                }
                try {
                    URI uri = new URI(origin);
                    String host = uri.getHost();
                    boolean bare = (uri.getPath() == null || uri.getPath().isEmpty())
                            && uri.getQuery() == null && uri.getFragment() == null;
                    if (!"https".equalsIgnoreCase(uri.getScheme()) || host == null || !bare) {
                        error(ORIGINS + " entry '" + origin + "' must look like https://host[:port] with no path");
                        continue;
                    }
                    String lowerHost = host.toLowerCase(Locale.ROOT);
                    String lowerRpId = rpId.toLowerCase(Locale.ROOT);
                    if (!rpId.isEmpty() && !lowerHost.equals(lowerRpId) && !lowerHost.endsWith("." + lowerRpId)) {
                        error(ORIGINS + " entry '" + origin + "' is not on " + RP_ID + " '" + rpId + "' or a subdomain of it");
                        continue;
                    }
                    result.add(origin.toLowerCase(Locale.ROOT));
                } catch (URISyntaxException e) {
                    error(ORIGINS + " entry '" + origin + "' is not a valid URL");
                }
            }
            if (result.isEmpty() && errors.isEmpty()) {
                error(ORIGINS + " has no usable entries");
            }
            return Collections.unmodifiableSet(result);
        }
    }
}
