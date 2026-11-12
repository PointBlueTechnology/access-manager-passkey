package com.pointbluetech.nam.login.passkey;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * eDirectory's own account restrictions, checked before a passwordless sign-in. A password sign-in
 * gets these from eDirectory refusing the bind; with only a passkey there is no bind. NAM's login
 * policy check (NMAS) runs as well, but this doesn't depend on what that policy covers. Anything
 * that can't be read or understood refuses.
 *
 * <p>Not covered here: time-of-day restrictions ({@code loginAllowedTimeMap}) and address
 * restrictions. The NAM user store's proxy account must be able to read these attributes; without
 * that right they read as absent, which can't be told apart from an account that has none.
 */
final class AccountRestrictions {

    static final String LOGIN_DISABLED = "loginDisabled";
    static final String LOCKED_BY_INTRUDER = "lockedByIntruder";
    static final String INTRUDER_RESET_TIME = "loginIntruderResetTime";
    static final String EXPIRATION_TIME = "loginExpirationTime";

    static final List<String> EDIRECTORY_ATTRIBUTES =
            List.of(LOGIN_DISABLED, LOCKED_BY_INTRUDER, INTRUDER_RESET_TIME, EXPIRATION_TIME);

    /** eDirectory GeneralizedTime, e.g. 20261110161710Z, with optional fractional seconds. */
    private static final Pattern GENERALIZED_TIME = Pattern.compile("^(\\d{14})(?:[.,]\\d+)?Z$");
    private static final DateTimeFormatter SECONDS = DateTimeFormatter.ofPattern("uuuuMMddHHmmss");

    private AccountRestrictions() {
    }

    /** @return why the account may not sign in, or empty if nothing stops it */
    static Optional<String> refusal(UserAttributes attributes, Instant now) {
        if (isTrue(attributes, LOGIN_DISABLED)) {
            return Optional.of("account disabled");
        }
        if (isTrue(attributes, LOCKED_BY_INTRUDER)) {
            Optional<Instant> reset = time(attributes, INTRUDER_RESET_TIME);
            // Without a reset time the lockout lasts until an administrator clears it
            if (!reset.isPresent() || now.isBefore(reset.get())) {
                return Optional.of("locked by intruder detection");
            }
        }
        Optional<Instant> expires = time(attributes, EXPIRATION_TIME);
        if (expires.isPresent() && !now.isBefore(expires.get())) {
            return Optional.of("account expired");
        }
        return Optional.empty();
    }

    private static boolean isTrue(UserAttributes attributes, String attribute) {
        List<String> values = attributes.read(attribute);
        for (String value : values) {
            String normalized = value.trim().toUpperCase(Locale.ROOT);
            if (!normalized.equals("TRUE") && !normalized.equals("FALSE")) {
                throw new PasskeyStoreException("Unexpected " + attribute + " value");
            }
            if (normalized.equals("TRUE")) {
                return true;
            }
        }
        return false;
    }

    private static Optional<Instant> time(UserAttributes attributes, String attribute) {
        List<String> values = attributes.read(attribute);
        if (values.isEmpty()) {
            return Optional.empty();
        }
        Matcher match = GENERALIZED_TIME.matcher(values.get(0).trim());
        if (!match.matches()) {
            throw new PasskeyStoreException("Unexpected " + attribute + " value");
        }
        try {
            return Optional.of(LocalDateTime.parse(match.group(1), SECONDS).toInstant(ZoneOffset.UTC));
        } catch (DateTimeParseException e) {
            throw new PasskeyStoreException("Unexpected " + attribute + " value", e);
        }
    }
}
