package com.pointbluetech.nam.login.passkey;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import javax.naming.NamingException;
import javax.naming.ldap.ExtendedRequest;
import javax.naming.ldap.ExtendedResponse;

/**
 * eDirectory's Get Effective Privileges extended operation, as JNDI can send it: what rights a
 * trustee has to one attribute of one entry. eDirectory answers a read the account may not make by
 * leaving the attribute out, exactly as if it had no value, so this is the only way to tell "not
 * set" from "not allowed to see".
 *
 * <p>The request is three BER OCTET STRINGs in a row, with no SEQUENCE around them: the entry's
 * DN, the trustee's DN and the attribute name. The response is one INTEGER of attribute rights.
 */
final class EffectivePrivileges {

    static final String REQUEST_OID = "2.16.840.1.113719.1.27.100.33";
    static final String RESPONSE_OID = "2.16.840.1.113719.1.27.100.34";

    /** eDirectory attribute rights. */
    static final int COMPARE = 0x01;
    static final int READ = 0x02;

    private EffectivePrivileges() {
    }

    static final class Request implements ExtendedRequest {

        private static final long serialVersionUID = 1L;

        private final byte[] value;

        /**
         * @param entryDn the entry whose attribute is asked about
         * @param trusteeDn the account whose rights are wanted
         * @param attribute the attribute name
         */
        Request(String entryDn, String trusteeDn, String attribute) {
            if (isBlank(entryDn) || isBlank(trusteeDn) || isBlank(attribute)) {
                throw new IllegalArgumentException("Entry DN, trustee DN and attribute are all required");
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            octetString(out, entryDn);
            octetString(out, trusteeDn);
            octetString(out, attribute);
            value = out.toByteArray();
        }

        @Override
        public String getID() {
            return REQUEST_OID;
        }

        @Override
        public byte[] getEncodedValue() {
            return value.clone();
        }

        @Override
        public ExtendedResponse createExtendedResponse(String id, byte[] berValue, int offset, int length)
                throws NamingException {
            if (id != null && !id.equals(RESPONSE_OID)) {
                throw new NamingException("Unexpected response " + id + " to Get Effective Privileges");
            }
            if (berValue == null) {
                throw new NamingException("Get Effective Privileges returned no value");
            }
            return new Response(decodeInteger(berValue, offset, length));
        }
    }

    static final class Response implements ExtendedResponse {

        private static final long serialVersionUID = 1L;

        private final int privileges;

        Response(int privileges) {
            this.privileges = privileges;
        }

        int privileges() {
            return privileges;
        }

        boolean canRead() {
            return privileges >= 0 && (privileges & READ) != 0;
        }

        @Override
        public String getID() {
            return RESPONSE_OID;
        }

        @Override
        public byte[] getEncodedValue() {
            return null;
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static void octetString(ByteArrayOutputStream out, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        out.write(0x04);
        length(out, bytes.length);
        out.write(bytes, 0, bytes.length);
    }

    /** BER definite length: short form below 128, long form otherwise. */
    private static void length(ByteArrayOutputStream out, int length) {
        if (length < 0x80) {
            out.write(length);
            return;
        }
        int bytes = length > 0xFFFFFF ? 4 : length > 0xFFFF ? 3 : length > 0xFF ? 2 : 1;
        out.write(0x80 | bytes);
        for (int i = bytes - 1; i >= 0; i--) {
            out.write(length >>> (8 * i));
        }
    }

    /** One BER INTEGER of at most four bytes, two's complement, filling the value exactly. */
    static int decodeInteger(byte[] ber, int offset, int length) throws NamingException {
        if (length < 3 || offset < 0 || offset + length > ber.length || ber[offset] != 0x02) {
            throw new NamingException("Get Effective Privileges returned something other than an INTEGER");
        }
        int size = ber[offset + 1] & 0xFF;
        if (size < 1 || size > 4 || 2 + size != length) {
            throw new NamingException("Get Effective Privileges returned a malformed INTEGER");
        }
        int result = ber[offset + 2]; // sign-extended
        for (int i = 1; i < size; i++) {
            result = (result << 8) | (ber[offset + 2 + i] & 0xFF);
        }
        return result;
    }
}
