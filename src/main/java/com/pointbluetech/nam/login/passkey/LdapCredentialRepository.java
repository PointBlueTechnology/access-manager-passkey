package com.pointbluetech.nam.login.passkey;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Yubico's view of the passkey attribute, scoped to the one user the current ceremony is for. The
 * library's "username" is the user's GUID, so it maps 1:1 to the user handle.
 *
 * {@link #lookupAll} only sees this user's passkeys: the attribute holds JSON, so the directory
 * can't be searched by credential ID. The library uses it to refuse duplicate registrations, which
 * this makes per-user. That's safe because lookups always go through the user, so a credential ID
 * copied onto another account could only ever match on that account.
 */
final class LdapCredentialRepository implements CredentialRepository {

    private final UserAccount account;
    private final PasskeyStore store;

    LdapCredentialRepository(UserAccount account, PasskeyStore store) {
        this.account = account;
        this.store = store;
    }

    /**
     * Sign-in asks with the GUID. Registration asks with the passkey's user name, which is the
     * directory name users see in their password manager; its answer becomes the exclude list, which
     * stops an authenticator that already holds one of this user's passkeys from making another, or
     * from silently replacing it.
     */
    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        if (!account.guid().equals(username) && !account.name().equals(username)) {
            return Collections.emptySet();
        }
        return store.load().stream()
                .map(PasskeyRecord::toDescriptor)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return account.guid().equals(username) ? Optional.of(account.userHandle()) : Optional.empty();
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return account.userHandle().equals(userHandle) ? Optional.of(account.guid()) : Optional.empty();
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        if (!account.userHandle().equals(userHandle)) {
            return Optional.empty();
        }
        return store.load().stream()
                .filter(record -> record.credentialId().equals(credentialId))
                .map(PasskeyRecord::toRegisteredCredential)
                .findFirst();
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return store.load().stream()
                .filter(record -> record.credentialId().equals(credentialId))
                .map(PasskeyRecord::toRegisteredCredential)
                .collect(Collectors.toSet());
    }
}
