package com.pointbluetech.nam.login.passkey;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Per-login state kept in the NAM session as plain strings. NAM creates new instances of the auth
 * class during a login, so nothing about a ceremony can live on the class itself.
 *
 * A ceremony request is single-use, expires, and only counts for the type and user it was issued for.
 */
final class CeremonyState {

    enum Type { ASSERTION, REGISTRATION }

    /** The parts of NIDPSession this needs; setting null clears a key. */
    interface Session {
        Object get(String key);
        void put(String key, Object value);
    }

    private static final String SEPARATOR = "|";
    private static final SecureRandom RANDOM = new SecureRandom();
    /**
     * A passkey proof, for the method that made it only: each method forgets it when it starts and
     * when it finishes, so it can't unlock a method in a contract started later in the same session,
     * which may have asked only for a password.
     */
    private static final String VERIFIED_KEY = "pbtPasskey.verified";

    private final Session session;
    private final String ceremonyKey;
    private final String enrollingKey;
    private final String messageKey;
    private final String tokenKey;
    private final String pendingKey;
    private final String recoveredKey;
    private final String recoveryEnrolledKey;
    private final String failedKey;
    private final String gatesKey;
    private final String gateCodeKey;
    private final String gateQuestionsKey;
    private final String gateNmasKey;
    private final String guid;
    private final long ttlMillis;
    private final Clock clock;

    CeremonyState(Session session, String scope, String guid, int ttlSec, Clock clock) {
        this.session = session;
        String prefix = "pbtPasskey." + scope + ".";
        this.ceremonyKey = prefix + "ceremony";
        this.enrollingKey = prefix + "enrolling";
        this.messageKey = prefix + "message";
        this.tokenKey = prefix + "token";
        this.pendingKey = prefix + "pending";
        this.recoveredKey = prefix + "recovered";
        this.recoveryEnrolledKey = prefix + "recoveryEnrolled";
        this.failedKey = prefix + "failed";
        this.gatesKey = prefix + "gates";
        this.gateCodeKey = prefix + "gateCode";
        this.gateQuestionsKey = prefix + "gateQuestions";
        this.gateNmasKey = prefix + "gateNmas";
        this.guid = guid;
        this.ttlMillis = ttlSec * 1000L;
        this.clock = clock;
    }

    void put(Type type, String requestJson) {
        session.put(ceremonyKey, type + SEPARATOR + guid + SEPARATOR + clock.millis() + SEPARATOR + requestJson);
    }

    /** Removes the stored request whatever happens; returns it only if it's valid for this call. */
    Optional<String> take(Type type) {
        Object stored = session.get(ceremonyKey);
        session.put(ceremonyKey, null);
        if (!(stored instanceof String)) {
            return Optional.empty();
        }
        String[] parts = ((String) stored).split("\\" + SEPARATOR, 4);
        if (parts.length != 4 || !type.name().equals(parts[0]) || !guid.equals(parts[1])) {
            return Optional.empty();
        }
        long issued;
        try {
            issued = Long.parseLong(parts[2]);
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
        return clock.millis() - issued > ttlMillis ? Optional.empty() : Optional.of(parts[3]);
    }

    /**
     * Whether this user registered their first passkey during this login. Only then may they add
     * another with just the earlier methods behind them; otherwise someone holding a stolen password
     * could add a passkey to an account that already has one.
     */
    boolean enrolling() {
        return guid.equals(session.get(enrollingKey));
    }

    void setEnrolling(boolean enrolling) {
        session.put(enrollingKey, enrolling ? guid : null);
    }

    /** A message waiting for the next rendered page, for when the frame page has to load first. */
    void setPendingMessage(String key) {
        session.put(messageKey, key);
    }

    Optional<String> takePendingMessage() {
        Object key = session.get(messageKey);
        session.put(messageKey, null);
        return key instanceof String ? Optional.of((String) key) : Optional.empty();
    }

    /** Records that this user just proved a passkey with user verification. */
    void markVerified() {
        markVerified(guid);
    }

    /** For sign-in, where this state is created before anyone knows who the user is. */
    void markVerified(String userGuid) {
        session.put(VERIFIED_KEY, userGuid + SEPARATOR + clock.millis());
    }

    boolean verifiedWithin(long seconds) {
        Object stored = session.get(VERIFIED_KEY);
        if (!(stored instanceof String)) {
            return false;
        }
        String[] parts = ((String) stored).split("\\" + SEPARATOR, 2);
        if (parts.length != 2 || !guid.equals(parts[0])) {
            return false;
        }
        try {
            return clock.millis() - Long.parseLong(parts[1]) <= seconds * 1000L;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * A token for the manage page's forms. Renaming and removing have no WebAuthn challenge to tie
     * them to this page, so without it another site could post them using the user's session.
     */
    String actionToken() {
        Object token = session.get(tokenKey);
        if (token instanceof String) {
            return (String) token;
        }
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String created = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        session.put(tokenKey, created);
        return created;
    }

    boolean checkActionToken(String candidate) {
        Object token = session.get(tokenKey);
        return token instanceof String && candidate != null
                && MessageDigest.isEqual(((String) token).getBytes(StandardCharsets.UTF_8),
                        candidate.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Remembers a manage action that was stopped only because the passkey proof had aged out, so it
     * can finish once the user has confirmed. It lasts as long as a challenge does.
     */
    void setPendingAction(String action, String credentialId, String name) {
        session.put(pendingKey, guid + SEPARATOR + clock.millis() + SEPARATOR + action + SEPARATOR
                + (credentialId == null ? "" : credentialId) + SEPARATOR + (name == null ? "" : name));
    }

    /** @return {action, credentialId, name}, if one is waiting and still fresh */
    Optional<String[]> takePendingAction() {
        Object stored = session.get(pendingKey);
        session.put(pendingKey, null);
        if (!(stored instanceof String)) {
            return Optional.empty();
        }
        String[] parts = ((String) stored).split("\\" + SEPARATOR, 5);
        if (parts.length != 5 || !guid.equals(parts[0])) {
            return Optional.empty();
        }
        try {
            if (clock.millis() - Long.parseLong(parts[1]) > ttlMillis) {
                return Optional.empty();
            }
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
        return Optional.of(new String[] {parts[2], parts[3], parts[4]});
    }

    /** A recovery code or token was accepted in this login; a new passkey must follow. */
    boolean recovered() {
        return guid.equals(session.get(recoveredKey));
    }

    void setRecovered() {
        session.put(recoveredKey, guid);
    }

    boolean recoveryEnrolled() {
        return guid.equals(session.get(recoveryEnrolledKey));
    }

    void setRecoveryEnrolled() {
        session.put(recoveryEnrolledKey, guid);
    }

    /** @return how many wrong recovery entries this login has now made */
    int addFailure() {
        int failures = failures() + 1;
        session.put(failedKey, Integer.toString(failures));
        return failures;
    }

    int failures() {
        Object stored = session.get(failedKey);
        return stored instanceof String ? Integer.parseInt((String) stored) : 0;
    }

    /** Whether this login has passed the named first-passkey check. */
    boolean gatePassed(String gate) {
        Object stored = session.get(gatesKey);
        if (!(stored instanceof String)) {
            return false;
        }
        String[] parts = ((String) stored).split("\\" + SEPARATOR, 2);
        return parts.length == 2 && guid.equals(parts[0]) && Arrays.asList(parts[1].split(",")).contains(gate);
    }

    void passGate(String gate) {
        if (gatePassed(gate)) {
            return;
        }
        Object stored = session.get(gatesKey);
        String passed = stored instanceof String && ((String) stored).startsWith(guid + SEPARATOR)
                ? ((String) stored).substring(guid.length() + 1) + "," : "";
        session.put(gatesKey, guid + SEPARATOR + passed + gate);
        // A spent code mustn't be tried again
        session.put(gateCodeKey, null);
        session.put(gateQuestionsKey, null);
        session.put(gateNmasKey, null);
    }

    /**
     * Keeps a hash of an emailed setup code, replacing any earlier one. The session is server-side,
     * but the code still isn't kept in a readable form.
     *
     * @return how many codes this login has now been sent
     */
    int issueGateCode(String code) {
        int sends = gateCodeSends() + 1;
        session.put(gateCodeKey, guid + SEPARATOR + clock.millis() + SEPARATOR + sends + SEPARATOR + hash(code));
        return sends;
    }

    int gateCodeSends() {
        String[] parts = gateCodeParts();
        return parts == null ? 0 : parseInt(parts[2]);
    }

    /** When the latest code was sent, in epoch milliseconds, or 0 if none was. */
    long gateCodeSentAt() {
        String[] parts = gateCodeParts();
        return parts == null ? 0 : parseLong(parts[1]);
    }

    /** Whether the input matches the latest code and it hasn't expired; it's used up once it matches. */
    boolean checkGateCode(String input, long ttlMillis) {
        String[] parts = gateCodeParts();
        if (parts == null || input == null || clock.millis() - parseLong(parts[1]) > ttlMillis) {
            return false;
        }
        boolean match = MessageDigest.isEqual(parts[3].getBytes(StandardCharsets.US_ASCII),
                hash(input.replaceAll("\\s", "")).getBytes(StandardCharsets.US_ASCII));
        if (match) {
            // Keeps the send count, so a later resend limit still holds; the code itself is gone
            session.put(gateCodeKey, parts[0] + SEPARATOR + parts[1] + SEPARATOR + parts[2] + SEPARATOR + "-");
        }
        return match;
    }

    /**
     * The security questions picked for this login, by position in the user's stored set, so the
     * same ones are checked when the answers come back. Tied to that stored set: if it changes, they're gone.
     */
    void setGateQuestions(String setFingerprint, List<Integer> indexes) {
        StringBuilder joined = new StringBuilder();
        for (int index : indexes) {
            joined.append(joined.length() == 0 ? "" : ",").append(index);
        }
        session.put(gateQuestionsKey, guid + SEPARATOR + setFingerprint + SEPARATOR + joined);
    }

    Optional<List<Integer>> gateQuestions(String setFingerprint) {
        Object stored = session.get(gateQuestionsKey);
        if (!(stored instanceof String)) {
            return Optional.empty();
        }
        String[] parts = ((String) stored).split("\\" + SEPARATOR, 3);
        if (parts.length != 3 || !guid.equals(parts[0]) || !parts[1].equals(setFingerprint) || parts[2].isEmpty()) {
            return Optional.empty();
        }
        List<Integer> indexes = new ArrayList<>();
        for (String index : parts[2].split(",")) {
            indexes.add(parseInt(index));
        }
        return Optional.of(indexes);
    }

    /** The NMAS login waiting for this user's security answers, by its ID; null forgets it. */
    void setGateNmas(String checkId) {
        session.put(gateNmasKey, checkId == null ? null : guid + SEPARATOR + checkId);
    }

    Optional<String> gateNmas() {
        Object stored = session.get(gateNmasKey);
        if (!(stored instanceof String) || !((String) stored).startsWith(guid + SEPARATOR)) {
            return Optional.empty();
        }
        return Optional.of(((String) stored).substring(guid.length() + 1));
    }

    private String[] gateCodeParts() {
        Object stored = session.get(gateCodeKey);
        if (!(stored instanceof String)) {
            return null;
        }
        String[] parts = ((String) stored).split("\\" + SEPARATOR, 4);
        return parts.length == 4 && guid.equals(parts[0]) ? parts : null;
    }

    private String hash(String code) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(guid.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            StringBuilder hex = new StringBuilder();
            for (byte b : digest.digest(code.getBytes(StandardCharsets.UTF_8))) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static int parseInt(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static long parseLong(String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** Forgets any passkey proof, whichever method made it. */
    void forgetVerified() {
        session.put(VERIFIED_KEY, null);
    }

    /** Clears this method's state. {@link #markVerified} survives; see {@link #forgetVerified}. */
    void clear() {
        session.put(ceremonyKey, null);
        session.put(enrollingKey, null);
        session.put(messageKey, null);
        session.put(tokenKey, null);
        session.put(pendingKey, null);
        session.put(recoveredKey, null);
        session.put(recoveryEnrolledKey, null);
        session.put(failedKey, null);
        session.put(gatesKey, null);
        session.put(gateCodeKey, null);
        session.put(gateQuestionsKey, null);
        session.put(gateNmasKey, null);
    }
}
