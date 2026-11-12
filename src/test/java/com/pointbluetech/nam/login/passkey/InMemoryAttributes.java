package com.pointbluetech.nam.login.passkey;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** A directory entry held in memory, with a count of writes and a switch to simulate an outage. */
final class InMemoryAttributes implements UserAttributes {

    final Map<String, List<String>> values = new HashMap<>();
    int writes;
    boolean readsFail;
    boolean writesFail;

    InMemoryAttributes() {
        values.put("objectClass", new ArrayList<>(List.of("top", "inetOrgPerson")));
    }

    @Override
    public List<String> read(String attribute) {
        if (readsFail) {
            throw new PasskeyStoreException("directory down");
        }
        return new ArrayList<>(values.getOrDefault(attribute, new ArrayList<>()));
    }

    @Override
    public void replace(String attribute, List<String> newValues) {
        if (writesFail) {
            throw new PasskeyStoreException("write refused");
        }
        writes++;
        if (newValues.isEmpty()) {
            values.remove(attribute);
        } else {
            values.put(attribute, new ArrayList<>(newValues));
        }
    }

    List<String> passkeyValues() {
        return values.getOrDefault("pbtPasskeyCredential", new ArrayList<>());
    }
}
