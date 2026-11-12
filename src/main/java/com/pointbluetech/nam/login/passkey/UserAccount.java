package com.pointbluetech.nam.login.passkey;

import com.yubico.webauthn.data.ByteArray;
import java.nio.charset.StandardCharsets;

/** The user a ceremony is for. The WebAuthn user handle is the UTF-8 bytes of the directory GUID. */
final class UserAccount {

    private static final int MAX_USER_HANDLE_BYTES = 64;

    private final String guid;
    private final String name;
    private final String displayName;
    private final ByteArray userHandle;

    /** @throws IllegalArgumentException if the GUID can't serve as a WebAuthn user handle */
    UserAccount(String guid, String name, String displayName) {
        if (guid == null || guid.isEmpty()) {
            throw new IllegalArgumentException("User has no GUID");
        }
        byte[] handle = guid.getBytes(StandardCharsets.UTF_8);
        if (handle.length > MAX_USER_HANDLE_BYTES) {
            throw new IllegalArgumentException("User GUID is longer than " + MAX_USER_HANDLE_BYTES + " bytes");
        }
        this.guid = guid;
        this.name = name;
        this.displayName = displayName == null || displayName.isEmpty() ? name : displayName;
        this.userHandle = new ByteArray(handle);
    }

    String guid() { return guid; }
    String name() { return name; }
    String displayName() { return displayName; }
    ByteArray userHandle() { return userHandle; }
}
