package com.pointbluetech.nam.login.passkey;

import com.novell.nam.common.ldap.jndi.IJNDINAMPreferredReplica;
import com.novell.nam.common.ldap.jndi.JNDIException;
import com.novell.nam.common.ldap.jndi.JNDIUserStore;
import com.novell.nam.common.ldap.jndi.JNDIUserStoreReplica;
import com.novell.nam.common.ldap.jndi.JNDIUserStoreReplicaConnection;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.authority.ldap.LDAPPrincipal;
import com.novell.nidp.common.authority.ldap.LDAPUserAuthority;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.AttributeInUseException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.NoSuchAttributeException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.ExtendedResponse;
import javax.naming.ldap.LdapName;

/** {@link UserAttributes} over NAM's user store, using the session's preferred replica. */
final class NamUserAttributes implements UserAttributes {

    private final NIDPPrincipal principal;
    private final UserAuthority authority;
    private final IJNDINAMPreferredReplica replica;

    NamUserAttributes(NIDPPrincipal principal, IJNDINAMPreferredReplica replica) {
        this.principal = principal;
        this.authority = principal.getAuthority();
        this.replica = replica;
        if (authority == null) {
            throw new PasskeyStoreException("Principal has no user store: " + principal.getUserIdentifier());
        }
    }

    @Override
    public List<String> read(String attribute) {
        // LDAPUserAuthority returns null when the search failed, and an empty set when the entry
        // simply has no value for the attribute
        Attributes attributes = authority.getAttributes(principal, new String[] {attribute}, replica);
        if (attributes == null) {
            throw new PasskeyStoreException("Could not read " + attribute + " of " + principal.getUserIdentifier());
        }
        List<String> values = new ArrayList<>();
        Attribute found = attributes.get(attribute);
        if (found == null) {
            return values;
        }
        try {
            NamingEnumeration<?> all = found.getAll();
            while (all.hasMore()) {
                Object value = all.next();
                values.add(value instanceof byte[]
                        ? new String((byte[]) value, StandardCharsets.UTF_8)
                        : String.valueOf(value));
            }
        } catch (NamingException e) {
            throw new PasskeyStoreException("Could not read " + attribute + " of " + principal.getUserIdentifier(), e);
        }
        return values;
    }

    /**
     * Whether the user store's proxy account, which every read here goes through, may read this
     * attribute of the user's entry. Asks eDirectory, since a read it may not make looks the same
     * as an attribute with no value.
     *
     * @throws PasskeyStoreException if eDirectory couldn't say
     */
    boolean canRead(String attribute) {
        String user = principal.getUserIdentifier();
        if (!(authority instanceof LDAPUserAuthority) || !(principal instanceof LDAPPrincipal)) {
            throw new PasskeyStoreException("Can't check the right to read " + attribute + " of " + user
                    + ": not an LDAP user store");
        }
        JNDIUserStore store = ((LDAPUserAuthority) authority).getStore();
        String proxy = store.getAdminUsername();
        String dn = ((LDAPPrincipal) principal).getDN();
        try {
            ExtendedResponse response = store.extendedOperation(new EffectivePrivileges.Request(dn, proxy, attribute),
                    replica);
            if (!(response instanceof EffectivePrivileges.Response)) {
                throw new PasskeyStoreException("Can't check the right to read " + attribute + " of " + user
                        + ": eDirectory gave no answer");
            }
            return ((EffectivePrivileges.Response) response).canRead();
        } catch (JNDIException | IllegalArgumentException e) {
            throw new PasskeyStoreException("Can't check the right to read " + attribute + " of " + user + ": " + e, e);
        }
    }

    /**
     * What a {@link #canRead} answer holds for: the proxy account, and the container the user is in,
     * whose ACLs normally decide what the proxy may read.
     */
    String rightsScope() {
        if (!(authority instanceof LDAPUserAuthority) || !(principal instanceof LDAPPrincipal)) {
            throw new PasskeyStoreException("Can't check read rights for " + principal.getUserIdentifier()
                    + ": not an LDAP user store");
        }
        String proxy = ((LDAPUserAuthority) authority).getStore().getAdminUsername();
        String dn = ((LDAPPrincipal) principal).getDN();
        String container;
        try {
            LdapName name = new LdapName(dn);
            container = name.size() > 1 ? name.getPrefix(name.size() - 1).toString() : dn;
        } catch (InvalidNameException | RuntimeException e) {
            // Unparseable: then the answer holds for this user alone
            container = dn;
        }
        return (proxy + '\n' + container).toLowerCase(Locale.ROOT);
    }

    /**
     * One LDAP modify, removing exactly the values that went and adding the new ones. eDirectory
     * applies it whole or not at all, and refuses it if a value to remove is already gone or one to
     * add already exists, which is how a value read by two requests at once can only be used by one of
     * them. NAM's own modify calls replace the whole attribute, so this borrows one admin connection
     * from NAM's pool, for the replica this session uses, and hands it straight back. Any failure
     * fails the request; nothing here retries or manages connections.
     */
    @Override
    public void change(String attribute, List<String> before, List<String> after) {
        Set<String> removed = UserAttributes.minus(before, after);
        Set<String> added = UserAttributes.minus(after, before);
        if (removed.isEmpty() && added.isEmpty()) {
            return;
        }
        String user = principal.getUserIdentifier();
        if (!(authority instanceof LDAPUserAuthority) || !(principal instanceof LDAPPrincipal)) {
            throw new PasskeyStoreException("Could not write " + attribute + " of " + user + ": not an LDAP user store");
        }
        List<ModificationItem> items = new ArrayList<>();
        for (String value : removed) {
            items.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(attribute, value)));
        }
        for (String value : added) {
            items.add(new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute(attribute, value)));
        }
        JNDIUserStoreReplica target = replicaFor(((LDAPUserAuthority) authority).getStore());
        if (target == null) {
            throw new PasskeyStoreException("Could not write " + attribute + " of " + user + ": no replica available");
        }
        JNDIUserStoreReplicaConnection connection = target.getAdminConnection();
        if (connection == null) {
            throw new PasskeyStoreException("Could not write " + attribute + " of " + user + ": no connection available");
        }
        try {
            DirContext context = connection.getDirContext();
            if (context == null) {
                throw new PasskeyStoreException("Could not write " + attribute + " of " + user + ": not connected");
            }
            context.modifyAttributes(((LDAPPrincipal) principal).getDN(), items.toArray(new ModificationItem[0]));
        } catch (NoSuchAttributeException | AttributeInUseException e) {
            throw new ConcurrentChangeException(attribute + " of " + user + " changed since it was read", e);
        } catch (NamingException e) {
            throw new PasskeyStoreException("Could not write " + attribute + " of " + user + ": " + e, e);
        } finally {
            target.putConnection(connection);
        }
    }

    /** The replica this session reads from, so a write is seen by the next read; else the first one up. */
    private JNDIUserStoreReplica replicaFor(JNDIUserStore store) {
        JNDIUserStoreReplica[] all = store.getUserStoreReplicas();
        if (all == null) {
            return null;
        }
        String preferred = replica == null ? null : replica.getPreferredReplicaId(store);
        JNDIUserStoreReplica first = null;
        for (JNDIUserStoreReplica candidate : all) {
            if (candidate == null || candidate.isBeingRestarted()) {
                continue;
            }
            if (preferred != null && preferred.equals(candidate.getId())) {
                return candidate;
            }
            if (first == null) {
                first = candidate;
            }
        }
        return first;
    }


}
