package com.pointbluetech.nam.login.passkey;

import com.yubico.webauthn.data.ByteArray;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.UnaryOperator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * One user's passkeys, kept as one attribute value per passkey.
 *
 * UserAuthority can only replace a multi-valued attribute as a whole, so every change reads the
 * current values, edits the list and writes it all back. Two simultaneous changes for the same user
 * can lose one of them; that's accepted (section 6 of the plan).
 */
final class PasskeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(PasskeyStore.class);
    private static final String OBJECT_CLASS = "objectClass";

    private final UserAttributes attributes;
    private final String attribute;
    private final String auxClass;

    PasskeyStore(UserAttributes attributes, String attribute, String auxClass) {
        this.attributes = attributes;
        this.attribute = attribute;
        this.auxClass = auxClass;
    }

    List<PasskeyRecord> load() {
        List<PasskeyRecord> records = new ArrayList<>();
        parse(attributes.read(attribute), records, new ArrayList<>());
        return records;
    }

    void update(UnaryOperator<List<PasskeyRecord>> change) {
        List<PasskeyRecord> records = new ArrayList<>();
        // Values we can't parse (corrupt, or written by a newer version) survive the rewrite
        List<String> unreadable = new ArrayList<>();
        parse(attributes.read(attribute), records, unreadable);

        List<String> values = new ArrayList<>(unreadable);
        for (PasskeyRecord record : change.apply(records)) {
            values.add(record.encode());
        }
        if (!values.isEmpty()) {
            ensureAuxClass(attributes, auxClass);
        }
        attributes.replace(attribute, values);
    }

    /**
     * Notes that a passkey was used, writing only if needed (see {@link PasskeyRecord#usageWriteNeeded}).
     *
     * @return its name, if this user has it
     */
    Optional<String> recordUse(ByteArray credentialId, long signCount, boolean backedUp, Instant now, long intervalSec) {
        Optional<PasskeyRecord> used = load().stream()
                .filter(record -> record.credentialId().equals(credentialId))
                .findFirst();
        if (used.isPresent() && used.get().usageWriteNeeded(signCount, backedUp, now, intervalSec)) {
            update(records -> {
                List<PasskeyRecord> updated = new ArrayList<>();
                for (PasskeyRecord record : records) {
                    updated.add(record.credentialId().equals(credentialId)
                            ? record.withUse(signCount, backedUp, now)
                            : record);
                }
                return updated;
            });
        }
        return used.map(PasskeyRecord::name);
    }

    private void parse(List<String> values, List<PasskeyRecord> records, List<String> unreadable) {
        for (String value : values) {
            try {
                records.add(PasskeyRecord.decode(value));
            } catch (IllegalArgumentException e) {
                unreadable.add(value);
            }
        }
        // Recovery codes, tokens, the last recovery time and SSPR's stored answers (ldapchai's default
        // attribute is carLicense too) can share this attribute, and aren't a problem
        long unknown = unreadable.stream()
                .filter(value -> !RecoveryStore.isRecoveryValue(value) && !value.startsWith(SsprResponses.RECORD_TYPE + "#"))
                .count();
        if (unknown > 0) {
            LOG.warn("Ignoring {} unreadable value(s) of {}", unknown, attribute);
        }
    }

    static void ensureAuxClass(UserAttributes attributes, String auxClass) {
        if (auxClass.isEmpty()) {
            return;
        }
        List<String> classes = attributes.read(OBJECT_CLASS);
        if (classes.isEmpty()) {
            // Replacing objectClass with only our class would damage the entry
            throw new PasskeyStoreException("Entry returned no objectClass values");
        }
        if (classes.stream().noneMatch(auxClass::equalsIgnoreCase)) {
            List<String> updated = new ArrayList<>(classes);
            updated.add(auxClass);
            attributes.replace(OBJECT_CLASS, updated);
        }
    }
}
