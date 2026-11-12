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
    private final boolean synced;
    private final boolean viaRecovery;

    PasskeyView(PasskeyRecord record) {
        this.id = record.credentialId().getBase64Url();
        this.name = record.name();
        this.provider = ProviderNames.forAaguid(record.aaguid()).orElse("");
        this.created = format(record.created());
        this.lastUsed = format(record.lastUsed());
        this.synced = record.backupEligible();
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
    public boolean synced() { return synced; }
    /** Created while recovering the account, so worth a second look if the user doesn't know it. */
    public boolean viaRecovery() { return viaRecovery; }
}
