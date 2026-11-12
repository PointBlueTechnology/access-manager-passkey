package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import javax.naming.NamingException;
import org.junit.jupiter.api.Test;

class EffectivePrivilegesTest {

    @Test
    void requestIsThreeOctetStringsWithNoSequence() {
        EffectivePrivileges.Request request = new EffectivePrivileges.Request("cn=u,o=x", "cn=p", "loginDisabled");

        assertEquals("2.16.840.1.113719.1.27.100.33", request.getID());
        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        for (String part : new String[] {"cn=u,o=x", "cn=p", "loginDisabled"}) {
            byte[] bytes = part.getBytes(StandardCharsets.UTF_8);
            expected.write(0x04);
            expected.write(bytes.length);
            expected.write(bytes, 0, bytes.length);
        }
        assertArrayEquals(expected.toByteArray(), request.getEncodedValue());
    }

    @Test
    void longValuesUseTheLongLengthForm() {
        String dn = "cn=" + "a".repeat(300) + ",o=x";
        byte[] value = new EffectivePrivileges.Request(dn, "cn=p", "loginDisabled").getEncodedValue();

        int length = dn.getBytes(StandardCharsets.UTF_8).length;
        assertEquals(0x04, value[0]);
        assertEquals((byte) 0x82, value[1]);
        assertEquals(length, ((value[2] & 0xFF) << 8) | (value[3] & 0xFF));
        assertEquals(0x04, value[4 + length]);
    }

    @Test
    void nonAsciiDnsAreUtf8() {
        byte[] value = new EffectivePrivileges.Request("cn=Jos\u00e9,o=x", "cn=p", "a").getEncodedValue();
        assertEquals("cn=Jos\u00e9,o=x".getBytes(StandardCharsets.UTF_8).length, value[1]);
    }

    @Test
    void blankPartsAreRefused() {
        assertThrows(IllegalArgumentException.class, () -> new EffectivePrivileges.Request("cn=u", "", "a"));
        assertThrows(IllegalArgumentException.class, () -> new EffectivePrivileges.Request("cn=u", null, "a"));
        assertThrows(IllegalArgumentException.class, () -> new EffectivePrivileges.Request("cn=u", "cn=p", " "));
    }

    @Test
    void responseReadsTheRights() throws Exception {
        assertTrue(response(new byte[] {0x02, 0x01, 0x03}).canRead()); // compare + read
        assertFalse(response(new byte[] {0x02, 0x01, 0x01}).canRead()); // compare only
        assertFalse(response(new byte[] {0x02, 0x01, 0x00}).canRead());
        assertEquals(0x0123, response(new byte[] {0x02, 0x02, 0x01, 0x23}).privileges());
        assertFalse(response(new byte[] {0x02, 0x01, (byte) 0xFF}).canRead()); // negative: not rights
    }

    @Test
    void responseHonoursOffsetAndLength() throws Exception {
        byte[] padded = {0x7F, 0x7F, 0x02, 0x01, 0x02, 0x7F};
        EffectivePrivileges.Request request = new EffectivePrivileges.Request("cn=u", "cn=p", "a");
        assertTrue(((EffectivePrivileges.Response) request.createExtendedResponse(
                EffectivePrivileges.RESPONSE_OID, padded, 2, 3)).canRead());
    }

    @Test
    void malformedResponsesAreErrors() {
        assertThrows(NamingException.class, () -> response(new byte[] {0x04, 0x01, 0x02}));
        assertThrows(NamingException.class, () -> response(new byte[] {0x02, 0x02, 0x02}));
        assertThrows(NamingException.class, () -> response(new byte[] {0x02, 0x05, 1, 2, 3, 4, 5}));
        assertThrows(NamingException.class, () -> response(new byte[0]));
        EffectivePrivileges.Request request = new EffectivePrivileges.Request("cn=u", "cn=p", "a");
        assertThrows(NamingException.class, () -> request.createExtendedResponse(
                "1.2.3", new byte[] {0x02, 0x01, 0x02}, 0, 3));
        assertThrows(NamingException.class, () -> request.createExtendedResponse(
                EffectivePrivileges.RESPONSE_OID, null, 0, 0));
    }

    private static EffectivePrivileges.Response response(byte[] value) throws NamingException {
        return (EffectivePrivileges.Response) new EffectivePrivileges.Request("cn=u", "cn=p", "a")
                .createExtendedResponse(EffectivePrivileges.RESPONSE_OID, value, 0, value.length);
    }
}
