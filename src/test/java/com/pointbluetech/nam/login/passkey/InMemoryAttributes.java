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
    /**
     * Runs once, just before the next change is applied: another request that read the same values
     * and finishes first.
     */
    Runnable beforeNextChange;

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
    public void change(String attribute, List<String> before, List<String> after) {
        Runnable other = beforeNextChange;
        if (other != null) {
            beforeNextChange = null;
            other.run();
        }
        if (writesFail) {
            throw new PasskeyStoreException("write refused");
        }
        List<String> current = values.getOrDefault(attribute, new ArrayList<>());
        java.util.Set<String> removed = UserAttributes.minus(before, after);
        java.util.Set<String> added = UserAttributes.minus(after, before);
        if (removed.isEmpty() && added.isEmpty()) {
            return;
        }
        // As eDirectory does: the whole change is refused if the attribute moved on since it was read
        for (String value : removed) {
            if (!current.contains(value)) {
                throw new ConcurrentChangeException(attribute + " no longer has a value being removed", null);
            }
        }
        for (String value : added) {
            if (current.contains(value)) {
                throw new ConcurrentChangeException(attribute + " already has a value being added", null);
            }
        }
        writes++;
        List<String> updated = new ArrayList<>(current);
        updated.removeAll(removed);
        updated.addAll(added);
        if (updated.isEmpty()) {
            values.remove(attribute);
        } else {
            values.put(attribute, updated);
        }
    }


    List<String> passkeyValues() {
        return values.getOrDefault("pbtPasskeyCredential", new ArrayList<>());
    }
}
