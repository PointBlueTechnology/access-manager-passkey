package com.pointbluetech.nam.login.passkey;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.exception.Base64UrlException;
import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * One registered passkey, stored as one value of the user's passkey attribute: {@code v1:} followed
 * by compact JSON. Immutable; see docs/DESIGN.md, Storage, for the format.
 */
public final class PasskeyRecord {

    private static final String PREFIX = "v1:";
    private static final ObjectMapper JSON = new ObjectMapper();

    private final ByteArray credentialId;
    private final ByteArray publicKeyCose;
    private final long signCount;
    private final ByteArray userHandle;
    private final String name;
    private final String aaguid;
    private final List<String> transports;
    private final boolean backupEligible;
    private final boolean backedUp;
    private final Boolean discoverable;
    private final Instant created;
    private final Instant lastUsed;
    private final boolean viaRecovery;

    private PasskeyRecord(ByteArray credentialId, ByteArray publicKeyCose, long signCount, ByteArray userHandle,
            String name, String aaguid, List<String> transports, boolean backupEligible, boolean backedUp,
            Boolean discoverable, Instant created, Instant lastUsed, boolean viaRecovery) {
        this.credentialId = credentialId;
        this.publicKeyCose = publicKeyCose;
        this.signCount = signCount;
        this.userHandle = userHandle;
        this.name = name;
        this.aaguid = aaguid;
        this.transports = Collections.unmodifiableList(transports);
        this.backupEligible = backupEligible;
        this.backedUp = backedUp;
        this.discoverable = discoverable;
        this.created = created;
        this.lastUsed = lastUsed;
        this.viaRecovery = viaRecovery;
    }

    static PasskeyRecord fromRegistration(RegistrationResult result, ByteArray userHandle, String name, Instant now,
            boolean viaRecovery) {
        List<String> transports = result.getKeyId().getTransports()
                .map(set -> set.stream().map(AuthenticatorTransport::getId).collect(Collectors.toList()))
                .orElseGet(ArrayList::new);
        return new PasskeyRecord(result.getKeyId().getId(), result.getPublicKeyCose(), result.getSignatureCount(),
                userHandle, name, result.getAaguid().getHex(), transports, result.isBackupEligible(),
                result.isBackedUp(), result.isDiscoverable().orElse(null), now, null, viaRecovery);
    }

    public ByteArray credentialId() { return credentialId; }
    public long signCount() { return signCount; }
    public String name() { return name; }
    public String aaguid() { return aaguid; }
    public boolean backupEligible() { return backupEligible; }
    public boolean backedUp() { return backedUp; }
    public Instant created() { return created; }
    public boolean viaRecovery() { return viaRecovery; }
    public Instant lastUsed() { return lastUsed; }

    RegisteredCredential toRegisteredCredential() {
        return RegisteredCredential.builder()
                .credentialId(credentialId)
                .userHandle(userHandle)
                .publicKeyCose(publicKeyCose)
                .signatureCount(signCount)
                .backupEligible(backupEligible)
                .backupState(backedUp)
                .build();
    }

    PublicKeyCredentialDescriptor toDescriptor() {
        Set<AuthenticatorTransport> set = new TreeSet<>();
        for (String transport : transports) {
            set.add(AuthenticatorTransport.of(transport));
        }
        return PublicKeyCredentialDescriptor.builder().id(credentialId).transports(set).build();
    }

    /**
     * Synced passkeys always report a sign count of 0, so writing on every login would mean an LDAP
     * write per login for nothing. Write when something changed, or when lastUsed has gone stale.
     */
    boolean usageWriteNeeded(long newSignCount, boolean newBackedUp, Instant now, long intervalSec) {
        return newSignCount > signCount
                || newBackedUp != backedUp
                || lastUsed == null
                || !lastUsed.plusSeconds(intervalSec).isAfter(now);
    }

    PasskeyRecord withUse(long newSignCount, boolean newBackedUp, Instant now) {
        return new PasskeyRecord(credentialId, publicKeyCose, newSignCount, userHandle, name, aaguid, transports,
                backupEligible, newBackedUp, discoverable, created, now, viaRecovery);
    }

    PasskeyRecord withName(String newName) {
        return new PasskeyRecord(credentialId, publicKeyCose, signCount, userHandle, newName, aaguid, transports,
                backupEligible, backedUp, discoverable, created, lastUsed, viaRecovery);
    }

    String encode() {
        ObjectNode node = JSON.createObjectNode();
        node.put("id", credentialId.getBase64Url());
        node.put("pk", publicKeyCose.getBase64Url());
        node.put("sc", signCount);
        node.put("uh", userHandle.getBase64Url());
        node.put("nm", name);
        node.put("aa", aaguid);
        ArrayNode tr = node.putArray("tr");
        transports.forEach(tr::add);
        node.put("be", backupEligible);
        node.put("bs", backedUp);
        if (discoverable != null) {
            node.put("disc", discoverable);
        }
        node.put("cr", created.truncatedTo(ChronoUnit.SECONDS).toString());
        if (lastUsed != null) {
            node.put("lu", lastUsed.truncatedTo(ChronoUnit.SECONDS).toString());
        }
        if (viaRecovery) {
            node.put("rv", true);
        }
        return PREFIX + node;
    }

    /** @throws IllegalArgumentException if the value isn't a readable v1 record */
    static PasskeyRecord decode(String value) {
        if (value == null || !value.startsWith(PREFIX)) {
            throw new IllegalArgumentException("Not a v1 passkey record");
        }
        try {
            JsonNode node = JSON.readTree(value.substring(PREFIX.length()));
            List<String> transports = new ArrayList<>();
            node.path("tr").forEach(t -> transports.add(t.asText()));
            return new PasskeyRecord(
                    bytes(node, "id"),
                    bytes(node, "pk"),
                    node.path("sc").asLong(0),
                    bytes(node, "uh"),
                    node.path("nm").asText(""),
                    node.path("aa").asText(""),
                    transports,
                    node.path("be").asBoolean(false),
                    node.path("bs").asBoolean(false),
                    node.has("disc") ? node.get("disc").asBoolean() : null,
                    Instant.parse(node.path("cr").asText()),
                    node.has("lu") ? Instant.parse(node.get("lu").asText()) : null,
                    node.path("rv").asBoolean(false));
        } catch (IOException | Base64UrlException | RuntimeException e) {
            throw new IllegalArgumentException("Unreadable passkey record", e);
        }
    }

    private static ByteArray bytes(JsonNode node, String field) throws Base64UrlException {
        JsonNode value = node.get(field);
        if (value == null || value.asText().isEmpty()) {
            throw new IllegalArgumentException("Missing " + field);
        }
        return ByteArray.fromBase64Url(value.asText());
    }
}
