package com.pointbluetech.nam.login.passkey;

import java.util.List;

/** Read and replace the values of one attribute on one user's directory entry. */
interface UserAttributes {

    /**
     * @return the values, empty if the user has no value for the attribute
     * @throws PasskeyStoreException if the entry could not be read. This must not look like "no
     *         values": a read failure treated as "no passkeys" would offer enrollment to someone
     *         holding only a password, and the following write would erase the real passkeys.
     */
    List<String> read(String attribute);

    /** Replaces all values of the attribute; an empty list removes it. */
    void replace(String attribute, List<String> values);
}
