package com.pointbluetech.nam.login.passkey;

import com.novell.nam.common.ldap.jndi.IJNDINAMPreferredReplica;
import com.novell.nidp.NIDPException;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.common.authority.UserAuthority;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

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

    @Override
    public void replace(String attribute, List<String> values) {
        // An empty string is how UserAuthority spells "remove the attribute"
        String[] array = values.isEmpty() ? new String[] {""} : values.toArray(new String[0]);
        try {
            authority.modifyAttributes(principal, new String[] {attribute}, array, replica);
        } catch (NIDPException e) {
            throw new PasskeyStoreException("Could not write " + attribute + " of " + principal.getUserIdentifier(), e);
        }
    }
}
