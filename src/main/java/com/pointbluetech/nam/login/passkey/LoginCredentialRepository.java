package com.pointbluetech.nam.login.passkey;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Yubico's view of every user's passkeys, for sign-in before the user is known. The library's
 * "username" is the user's GUID, as in {@link LdapCredentialRepository}.
 *
 * It also answers for decoy usernames: an ID with no passkeys gets a made-up credential that stays
 * the same for that ID, so the login page can't be used to find out which accounts exist or have
 * passkeys. The browser reports that nothing matched, exactly as if the user had cancelled. Each
 * decoy takes the length and transports of one of a few common kinds of passkey, chosen by the ID,
 * so it doesn't stand out by shape. A real user with several passkeys still lists that many.
 */
final class LoginCredentialRepository implements CredentialRepository {

    private static final String DECOY_PREFIX = "decoy:";
    private static final String HMAC = "HmacSHA256";
    /**
     * Only when no RECOVERY_PEPPER is set: then decoys differ between cluster nodes and across
     * restarts, which a real user's credentials don't, so comparing nodes can tell them apart.
     */
    private static final byte[] JVM_DECOY_KEY = newDecoyKey();

    private final UserDirectory directory;
    private final byte[] decoyKey;
    /**
     * Common shapes of real passkeys: credential ID length in bytes, and transports. A decoy takes one,
     * weighted by how often it's listed here, so its length and transports are like a real one's.
     */
    private static final DecoyShape[] DECOY_SHAPES = {
        new DecoyShape(16, AuthenticatorTransport.HYBRID, AuthenticatorTransport.INTERNAL),
        new DecoyShape(16, AuthenticatorTransport.HYBRID, AuthenticatorTransport.INTERNAL),
        new DecoyShape(20, AuthenticatorTransport.HYBRID, AuthenticatorTransport.INTERNAL),
        new DecoyShape(20, AuthenticatorTransport.HYBRID, AuthenticatorTransport.INTERNAL),
        new DecoyShape(32, AuthenticatorTransport.HYBRID, AuthenticatorTransport.INTERNAL),
        new DecoyShape(32, AuthenticatorTransport.INTERNAL),
        new DecoyShape(48, AuthenticatorTransport.NFC, AuthenticatorTransport.USB),
        new DecoyShape(64, AuthenticatorTransport.NFC, AuthenticatorTransport.USB),
    };

    private static final class DecoyShape {
        final int length;
        final Set<AuthenticatorTransport> transports;

        DecoyShape(int length, AuthenticatorTransport... transports) {
            this.length = length;
            // Sorted, as a real passkey's are
            this.transports = Collections.unmodifiableSet(new TreeSet<>(java.util.Arrays.asList(transports)));
        }
    }

    /** One lookup per user per request; the library asks several times during a ceremony. */
    private final Map<String, Optional<UserDirectory.User>> users = new HashMap<>();
    /** One read of each user's passkeys per request. */
    private final Map<String, java.util.List<PasskeyRecord>> passkeys = new HashMap<>();

    LoginCredentialRepository(UserDirectory directory) {
        this(directory, Optional.empty(), "");
    }

    /**
     * @param sharedSecret the class's RECOVERY_PEPPER, the same on every node, so an ID gets the
     *        same decoy whichever node answers and after a restart
     */
    LoginCredentialRepository(UserDirectory directory, Optional<byte[]> sharedSecret, String rpId) {
        this.directory = directory;
        this.decoyKey = sharedSecret.map(secret -> derive(secret, "pbt-passkey decoy credential v1|" + rpId))
                .orElse(JVM_DECOY_KEY);
    }

    private static byte[] derive(byte[] secret, String label) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(secret, HMAC));
            return mac.doFinal(label.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    static String decoyUsername(String id) {
        return DECOY_PREFIX + id.toLowerCase(Locale.ROOT);
    }

    Optional<UserDirectory.User> user(String guid) {
        return users.computeIfAbsent(guid, directory::byGuid);
    }

    /**
     * Keeps a user already found by ID, so building their challenge doesn't search the directory
     * again: that extra search would make a real user's answer slower than a decoy's.
     */
    void remember(UserDirectory.User user) {
        users.put(user.account().guid(), Optional.of(user));
    }

    /** The user's passkeys, read once per request. */
    java.util.List<PasskeyRecord> passkeys(UserDirectory.User user) {
        return passkeys.computeIfAbsent(user.account().guid(), guid -> user.store().load());
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        if (username.startsWith(DECOY_PREFIX)) {
            return Collections.singleton(decoyDescriptor(username));
        }
        return user(username)
                .map(found -> passkeys(found).stream()
                        .map(PasskeyRecord::toDescriptor)
                        .collect(Collectors.toCollection(LinkedHashSet::new)))
                .orElseGet(LinkedHashSet::new);
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return username.startsWith(DECOY_PREFIX)
                ? Optional.empty()
                : user(username).map(found -> found.account().userHandle());
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        String guid = new String(userHandle.getBytes(), StandardCharsets.UTF_8);
        return user(guid).map(found -> found.account().guid());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        String guid = new String(userHandle.getBytes(), StandardCharsets.UTF_8);
        return user(guid).flatMap(found -> passkeys(found).stream()
                .filter(record -> record.credentialId().equals(credentialId))
                .map(PasskeyRecord::toRegisteredCredential)
                .findFirst());
    }

    /** The attribute holds JSON, so it can't be searched by credential ID; only registration needs this. */
    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return Collections.emptySet();
    }

    /**
     * The same for an ID every time, on every node: its shape and its bytes both come from an HMAC of
     * the ID, so asking again shows nothing new.
     */
    PublicKeyCredentialDescriptor decoyDescriptor(String username) {
        byte[] seed = hmac("shape|" + username);
        DecoyShape shape = DECOY_SHAPES[(seed[0] & 0xFF) % DECOY_SHAPES.length];
        byte[] id = new byte[shape.length];
        for (int filled = 0, block = 0; filled < id.length; block++) {
            byte[] bytes = hmac("id|" + block + "|" + username);
            int take = Math.min(bytes.length, id.length - filled);
            System.arraycopy(bytes, 0, id, filled, take);
            filled += take;
        }
        return PublicKeyCredentialDescriptor.builder()
                .id(new ByteArray(id))
                .transports(shape.transports)
                .build();
    }

    private byte[] hmac(String input) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(decoyKey, HMAC));
            return mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    private static byte[] newDecoyKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }
}
