package com.pointbluetech.nam.login.passkey;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;

/**
 * What a page passes to the user's password manager through the WebAuthn Signals API, as JSON for
 * {@code PbtPasskey.signal()}. They're hints: the browser hands them on and reports nothing back.
 *
 * A wrong list would make password managers drop passkeys that still work, so the class sends one
 * only from a fresh, successful read, never an empty one, and only in a login where the user just
 * proved a passkey from that same attribute.
 */
final class PasswordManagerSignals {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final String rpId;
    private final ObjectNode root = JSON.createObjectNode();

    PasswordManagerSignals(String rpId) {
        this.rpId = rpId;
    }

    /**
     * Every passkey this user still has, which password managers keep while hiding the rest, and
     * the user's current names, for the labels they show.
     *
     * @throws IllegalArgumentException for an empty list, which would hide every passkey the user has
     */
    PasswordManagerSignals accepted(UserAccount account, List<PasskeyRecord> passkeys) {
        if (passkeys.isEmpty()) {
            throw new IllegalArgumentException("Refusing to signal an empty passkey list");
        }
        String userId = account.userHandle().getBase64Url();
        ObjectNode accepted = root.putObject("accepted");
        accepted.put("rpId", rpId);
        accepted.put("userId", userId);
        ArrayNode ids = accepted.putArray("allAcceptedCredentialIds");
        for (PasskeyRecord passkey : passkeys) {
            ids.add(passkey.credentialId().getBase64Url());
        }
        ObjectNode user = root.putObject("user");
        user.put("rpId", rpId);
        user.put("userId", userId);
        user.put("name", account.name());
        user.put("displayName", account.displayName());
        return this;
    }

    /** A passkey this site definitely doesn't have, which password managers then remove. */
    PasswordManagerSignals unknown(String credentialId) {
        ArrayNode unknown = root.has("unknown") ? (ArrayNode) root.get("unknown") : root.putArray("unknown");
        unknown.addObject().put("rpId", rpId).put("credentialId", credentialId);
        return this;
    }

    boolean isEmpty() {
        return root.isEmpty();
    }

    /** @return JSON safe to place in a {@code <script type="application/json">} block */
    String toScriptJson() {
        try {
            return PasskeyMessages.jsonForScriptTag(JSON.writeValueAsString(root));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not serialize password manager signals", e);
        }
    }
}
