package com.pointbluetech.nam.login.passkey;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * One user's recovery codes and helpdesk token. Only HMACs are stored, keyed with the pepper from NAM's
 * configuration, which production keeps in a separate, more restricted directory than the users. The
 * values are also 80 random bits, so they can't be guessed back even if both directories leak. Values
 * are prefixed so they can share an attribute with passkeys, which {@link PasskeyStore} leaves alone.
 */
final class RecoveryStore {

    enum Match { NONE, CODE, TOKEN }

    /** A newly issued helpdesk token, shown once. */
    static final class IssuedToken {
        final String display;
        final Instant expires;

        IssuedToken(String display, Instant expires) {
            this.display = display;
            this.expires = expires;
        }
    }

    static final String CODE_PREFIX = "rc1:";
    static final String TOKEN_PREFIX = "et1:";
    /** When the account was last recovered, in epoch milliseconds; kept with the codes. */
    static final String RECOVERED_PREFIX = "rr1:";

    private static final String HMAC = "HmacSHA256";
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int CODE_CHARS = 16;
    private static final int TOKEN_CHARS = 16;
    private static final int MAX_INPUT_CHARS = 64;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserAttributes attributes;
    private final String codeAttribute;
    private final String tokenAttribute;
    private final String auxClass;
    private final byte[] pepper;
    private final String guid;
    private final int maxFailed;
    private final Clock clock;

    RecoveryStore(UserAttributes attributes, String codeAttribute, String tokenAttribute, String auxClass,
            byte[] pepper, String guid, int maxFailed, Clock clock) {
        this.attributes = attributes;
        this.codeAttribute = codeAttribute;
        this.tokenAttribute = tokenAttribute;
        this.auxClass = auxClass;
        this.pepper = pepper;
        this.guid = guid;
        this.maxFailed = maxFailed;
        this.clock = clock;
    }

    /** Replaces any existing codes. @return the new codes, for showing once; never stored or logged */
    List<String> generateCodes(int count) {
        List<String> display = new ArrayList<>();
        List<String> hashes = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String code = random(CODE_CHARS);
            display.add(group(code));
            hashes.add(CODE_PREFIX + hmac(code));
        }
        PasskeyStore.ensureAuxClass(attributes, auxClass);
        attributes.update(codeAttribute, before -> {
            List<String> values = withoutPrefix(before, CODE_PREFIX);
            values.addAll(hashes);
            return values;
        });
        return display;
    }

    int codesLeft() {
        int count = 0;
        for (String value : attributes.read(codeAttribute)) {
            if (value.startsWith(CODE_PREFIX)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Records that the account was recovered just now. Kept apart from the passkeys, so deleting the
     * passkey made during recovery can't end a cool-down.
     */
    void markRecovered() {
        String recovered = RECOVERED_PREFIX + clock.millis();
        PasskeyStore.ensureAuxClass(attributes, auxClass);
        attributes.update(codeAttribute, before -> {
            List<String> values = withoutPrefix(before, RECOVERED_PREFIX);
            values.add(recovered);
            return values;
        });
    }

    /** When the account was last recovered, if ever. */
    Optional<Instant> recoveredAt() {
        long latest = -1;
        for (String value : attributes.read(codeAttribute)) {
            if (value.startsWith(RECOVERED_PREFIX)) {
                latest = Math.max(latest, parseLong(value.substring(RECOVERED_PREFIX.length())));
            }
        }
        return latest > 0 ? Optional.of(Instant.ofEpochMilli(latest)) : Optional.empty();
    }

    /**
     * When new recovery codes may be created again, if a recent recovery holds them back. Someone who
     * recovered the account first then can't lock its owner out with codes of their own while the
     * owner has time to see the email and react.
     */
    Optional<Instant> codesBlockedUntil(long cooldownSec) {
        if (cooldownSec <= 0) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        return recoveredAt().map(at -> at.plusSeconds(cooldownSec)).filter(until -> until.isAfter(now));
    }

    static boolean isRecoveryValue(String value) {
        return value.startsWith(CODE_PREFIX) || value.startsWith(TOKEN_PREFIX) || value.startsWith(RECOVERED_PREFIX);
    }

    /** Replaces any existing token for this user. */
    IssuedToken issueToken(long ttlSec) {
        String token = random(TOKEN_CHARS);
        Instant expires = clock.instant().plusSeconds(ttlSec);
        String issued = TOKEN_PREFIX + hmac(token) + ":" + expires.toEpochMilli() + ":0";
        PasskeyStore.ensureAuxClass(attributes, auxClass);
        attributes.update(tokenAttribute, before -> {
            List<String> values = withoutPrefix(before, TOKEN_PREFIX);
            values.add(issued);
            return values;
        });
        return new IssuedToken(group(token), expires);
    }

    /**
     * Checks what the user typed against their codes and token, and uses up whichever matches. A wrong
     * entry counts against a waiting token, which is removed after too many tries or once expired.
     */
    Match consume(String input) {
        String normalized = normalize(input);
        if (normalized.isEmpty() || normalized.length() > MAX_INPUT_CHARS) {
            return Match.NONE;
        }
        String candidate = hmac(normalized);
        if (consumeCode(candidate)) {
            return Match.CODE;
        }
        return consumeTokenHash(candidate) ? Match.TOKEN : Match.NONE;
    }

    /** Like {@link #consume}, but only a helpdesk token counts: for a first passkey, not a recovery. */
    boolean consumeToken(String input) {
        String normalized = normalize(input);
        if (normalized.isEmpty() || normalized.length() > MAX_INPUT_CHARS) {
            return false;
        }
        return consumeTokenHash(hmac(normalized));
    }

    /**
     * Removes the matching code in one directory change that fails if the code is already gone, so of
     * two requests using the same code at once, only one gets it.
     */
    private boolean consumeCode(String candidate) {
        List<String> values = attributes.read(codeAttribute);
        String matched = null;
        // Looks at every value, so the time taken doesn't depend on which one matched
        for (String value : values) {
            if (value.startsWith(CODE_PREFIX) && same(value.substring(CODE_PREFIX.length()), candidate)) {
                matched = value;
            }
        }
        if (matched == null) {
            return false;
        }
        List<String> after = new ArrayList<>(values);
        after.remove(matched);
        return changeOnce(codeAttribute, values, after);
    }

    /**
     * Counts a wrong entry against the waiting token, removing it at MAX_FAILED. Retried on a clash, so
     * wrong entries sent at the same moment are each counted.
     */
    private void countWrongEntry(String tokenHash) {
        String prefix = TOKEN_PREFIX + tokenHash + ":";
        attributes.update(tokenAttribute, before -> {
            List<String> after = new ArrayList<>();
            for (String value : before) {
                if (!value.startsWith(prefix)) {
                    after.add(value);
                    continue;
                }
                String[] parts = value.substring(TOKEN_PREFIX.length()).split(":");
                long failed = (parts.length == 3 ? parseLong(parts[2]) : maxFailed) + 1;
                if (failed < maxFailed) {
                    after.add(prefix + parts[1] + ":" + failed);
                }
            }
            return after;
        });
    }

    /** One attempt; false if another request changed the attribute first, as when it used the same value. */
    private boolean changeOnce(String attribute, List<String> before, List<String> after) {
        try {
            attributes.change(attribute, before, after);
            return true;
        } catch (ConcurrentChangeException e) {
            return false;
        }
    }

    private boolean consumeTokenHash(String candidate) {
        List<String> values = attributes.read(tokenAttribute);
        for (String value : values) {
            if (!value.startsWith(TOKEN_PREFIX)) {
                continue;
            }
            String[] parts = value.substring(TOKEN_PREFIX.length()).split(":");
            List<String> others = new ArrayList<>(values);
            others.remove(value);
            if (parts.length != 3 || clock.millis() > parseLong(parts[1])) {
                changeOnce(tokenAttribute, values, others);
                return false;
            }
            if (same(parts[0], candidate)) {
                // Removed in a change that fails if the token is already gone: it works only once
                return changeOnce(tokenAttribute, values, others);
            }
            countWrongEntry(parts[0]);
            return false;
        }
        return false;
    }

    private static List<String> withoutPrefix(List<String> values, String prefix) {
        List<String> kept = new ArrayList<>();
        for (String value : values) {
            if (!value.startsWith(prefix)) {
                kept.add(value);
            }
        }
        return kept;
    }

    private static long parseLong(String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static boolean same(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.US_ASCII), b.getBytes(StandardCharsets.US_ASCII));
    }

    /** Forgives dashes, spaces and lower case. */
    private static String normalize(String input) {
        return input == null ? "" : input.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]", "");
    }

    /** Tied to the user, so one user's code value is useless copied onto another account. */
    private String hmac(String normalized) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(pepper, HMAC));
            mac.update(guid.getBytes(StandardCharsets.UTF_8));
            mac.update((byte) 0);
            StringBuilder hex = new StringBuilder();
            for (byte b : mac.doFinal(normalized.getBytes(StandardCharsets.UTF_8))) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    private static String random(int chars) {
        StringBuilder result = new StringBuilder(chars);
        for (int i = 0; i < chars; i++) {
            result.append(BASE32.charAt(RANDOM.nextInt(BASE32.length())));
        }
        return result.toString();
    }

    private static String group(String value) {
        return value.replaceAll("(.{4})(?=.)", "$1-");
    }
}
