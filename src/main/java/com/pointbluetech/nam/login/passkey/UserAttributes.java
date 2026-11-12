package com.pointbluetech.nam.login.passkey;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.UnaryOperator;

/** Read and change the values of one attribute on one user's directory entry. */
interface UserAttributes {

    /** Attempts at a read-and-change before giving up on an attribute that keeps changing. */
    int CHANGE_ATTEMPTS = 3;

    /**
     * @return the values, empty if the user has no value for the attribute
     * @throws PasskeyStoreException if the entry could not be read. This must not look like "no
     *         values": a read failure treated as "no passkeys" would offer enrollment to someone
     *         holding only a password, and the following write would erase the real passkeys.
     */
    List<String> read(String attribute);

    /**
     * Changes the attribute from {@code before}, as just read, to {@code after}, in one atomic directory
     * change that removes only the values that went and adds only the new ones. Values neither list
     * mentions, such as those written meanwhile by someone else, are left alone.
     *
     * @throws ConcurrentChangeException if a value to remove is already gone or one to add is already
     *         there, because the attribute changed after it was read; nothing is written then
     */
    void change(String attribute, List<String> before, List<String> after);

    /**
     * Reads the attribute, edits the values and writes the change, starting again from a fresh read
     * if someone else changed the attribute in between.
     *
     * @return the values as written
     */
    default List<String> update(String attribute, UnaryOperator<List<String>> edit) {
        for (int attempt = 1; ; attempt++) {
            List<String> before = read(attribute);
            List<String> after = edit.apply(new ArrayList<>(before));
            try {
                change(attribute, before, after);
                return after;
            } catch (ConcurrentChangeException e) {
                if (attempt >= CHANGE_ATTEMPTS) {
                    throw new PasskeyStoreException("Gave up writing " + attribute + ": it kept changing", e);
                }
            }
        }
    }

    /** The values in {@code from} that aren't in {@code without}. */
    static Set<String> minus(List<String> from, List<String> without) {
        Set<String> result = new LinkedHashSet<>(from);
        result.removeAll(without);
        return result;
    }
}
