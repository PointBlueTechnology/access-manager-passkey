package com.pointbluetech.nam.login.passkey;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/** One row of the manage page. Public for the JSP; values are not escaped here. */
public final class PasskeyView {

    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);

    private final String id;
    private final String name;
    private final String provider;
    private final String created;
    private final String lastUsed;
    private final String backupKey;
    private final boolean viaRecovery;

    PasskeyView(PasskeyRecord record) {
        this.id = record.credentialId().getBase64Url();
        this.name = record.name();
        this.provider = ProviderNames.forAaguid(record.aaguid()).orElse("");
        this.created = format(record.created());
        this.lastUsed = format(record.lastUsed());
        // Backed up now, able to be but not yet (as just after creating it), or never: one device only
        this.backupKey = record.backedUp() ? "manage.synced"
                : record.backupEligible() ? "manage.notSyncedYet" : "manage.deviceOnly";
        this.viaRecovery = record.viaRecovery();
    }

    private static String format(Instant instant) {
        return instant == null ? "" : DATE.format(instant);
    }

    public String id() { return id; }
    public String name() { return name; }
    public String provider() { return provider; }
    public String created() { return created; }
    /** Empty if never used. */
    public String lastUsed() { return lastUsed; }
    /** The message key describing whether the passkey is backed up by its provider. */
    public String backupKey() { return backupKey; }
    /** Created while recovering the account, so worth a second look if the user doesn't know it. */
    public boolean viaRecovery() { return viaRecovery; }
}
