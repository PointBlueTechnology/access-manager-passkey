package com.pointbluetech.nam.login.passkey;

import java.util.Optional;

/** Finds users before anyone has signed in, for LOGIN mode. */
interface UserDirectory {

    /** A user and where their passkeys live. The principal is opaque here; NAM code casts it back. */
    final class User {
        private final UserAccount account;
        private final PasskeyStore store;
        private final Object principal;

        User(UserAccount account, PasskeyStore store, Object principal) {
            this.account = account;
            this.store = store;
            this.principal = principal;
        }

        UserAccount account() { return account; }
        PasskeyStore store() { return store; }
        Object principal() { return principal; }
    }

    Optional<User> byGuid(String guid);

    /** @return the user with this sign-in ID, only if it matches exactly one */
    Optional<User> byId(String id);
}
