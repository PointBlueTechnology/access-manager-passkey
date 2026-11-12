package com.pointbluetech.nam.login.passkey;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.ByteArray;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

/**
 * A software authenticator plus browser: answers the option JSON the server sends with the response
 * JSON that passkey_common.jspf posts back, signing with a real P-256 key.
 */
final class VirtualAuthenticator {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final int FLAG_UP = 0x01;
    private static final int FLAG_UV = 0x04;
    private static final int FLAG_BE = 0x08;
    private static final int FLAG_BS = 0x10;
    private static final int FLAG_AT = 0x40;

    final KeyPair keys;
    final byte[] credentialId = new byte[32];
    final String origin;
    final String rpId;
    byte[] userHandle;
    long counter;
    boolean userVerified = true;
    boolean synced;
    Boolean reportDiscoverable = true;
    byte[] aaguid = new byte[16];
    /** When set, registration sends "packed" attestation signed with this key and certificate. */
    KeyPair attestationKey;
    X509Certificate attestationCertificate;

    VirtualAuthenticator(String origin, String rpId, long seed) throws Exception {
        this.origin = origin;
        this.rpId = rpId;
        new Random(seed).nextBytes(credentialId);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        keys = generator.generateKeyPair();
    }

    ByteArray id() {
        return new ByteArray(credentialId);
    }

    /** Answers {@code navigator.credentials.create()} options. */
    String create(String optionsJson) throws Exception {
        JsonNode options = JSON.readTree(optionsJson).get("publicKey");
        userHandle = Base64.getUrlDecoder().decode(options.get("user").get("id").asText());
        byte[] clientData = clientData("webauthn.create", options.get("challenge").asText());

        ByteArrayOutputStream authData = new ByteArrayOutputStream();
        authData.write(authDataPrefix(FLAG_AT));
        authData.write(aaguid);
        authData.write(ByteBuffer.allocate(2).putShort((short) credentialId.length).array());
        authData.write(credentialId);
        authData.write(coseKey());

        CBORObject attestation = CBORObject.NewMap();
        if (attestationKey == null) {
            attestation.Add("fmt", "none");
            attestation.Add("attStmt", CBORObject.NewMap());
        } else {
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(attestationKey.getPrivate());
            signer.update(authData.toByteArray());
            signer.update(sha256(clientData));
            CBORObject statement = CBORObject.NewMap();
            statement.Add("alg", -7);
            statement.Add("sig", signer.sign());
            statement.Add("x5c", CBORObject.NewArray().Add(attestationCertificate.getEncoded()));
            attestation.Add("fmt", "packed");
            attestation.Add("attStmt", statement);
        }
        attestation.Add("authData", authData.toByteArray());

        ObjectNode response = JSON.createObjectNode();
        response.put("clientDataJSON", B64.encodeToString(clientData));
        response.put("attestationObject", B64.encodeToString(attestation.EncodeToBytes()));
        response.putArray("transports").add("internal").add("hybrid");

        ObjectNode extensions = JSON.createObjectNode();
        if (reportDiscoverable != null) {
            extensions.putObject("credProps").put("rk", reportDiscoverable);
        }
        return envelope(response, extensions);
    }

    /** Answers {@code navigator.credentials.get()} options. */
    String get(String optionsJson) throws Exception {
        JsonNode options = JSON.readTree(optionsJson).get("publicKey");
        byte[] clientData = clientData("webauthn.get", options.get("challenge").asText());
        counter++;
        byte[] authData = authDataPrefix(0);

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keys.getPrivate());
        signer.update(authData);
        signer.update(sha256(clientData));

        ObjectNode response = JSON.createObjectNode();
        response.put("clientDataJSON", B64.encodeToString(clientData));
        response.put("authenticatorData", B64.encodeToString(authData));
        response.put("signature", B64.encodeToString(signer.sign()));
        if (userHandle != null) {
            response.put("userHandle", B64.encodeToString(userHandle));
        }
        return envelope(response, JSON.createObjectNode());
    }

    private String envelope(ObjectNode response, ObjectNode extensions) {
        ObjectNode credential = JSON.createObjectNode();
        credential.put("id", B64.encodeToString(credentialId));
        credential.put("rawId", B64.encodeToString(credentialId));
        credential.put("type", "public-key");
        credential.put("authenticatorAttachment", "platform");
        credential.set("clientExtensionResults", extensions);
        credential.set("response", response);
        return credential.toString();
    }

    private byte[] clientData(String type, String challenge) throws Exception {
        ObjectNode data = JSON.createObjectNode();
        data.put("type", type);
        data.put("challenge", challenge);
        data.put("origin", origin);
        data.put("crossOrigin", false);
        return data.toString().getBytes(StandardCharsets.UTF_8);
    }

    private byte[] authDataPrefix(int extraFlags) throws Exception {
        int flags = FLAG_UP | extraFlags
                | (userVerified ? FLAG_UV : 0)
                | (synced ? FLAG_BE | FLAG_BS : 0);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
        out.write(flags);
        out.write(ByteBuffer.allocate(4).putInt((int) counter).array());
        return out.toByteArray();
    }

    private byte[] coseKey() {
        ECPoint point = ((ECPublicKey) keys.getPublic()).getW();
        CBORObject key = CBORObject.NewMap();
        key.Add(1, 2);    // kty: EC2
        key.Add(3, -7);   // alg: ES256
        key.Add(-1, 1);   // crv: P-256
        key.Add(-2, unsigned32(point.getAffineX()));
        key.Add(-3, unsigned32(point.getAffineY()));
        return key.EncodeToBytes();
    }

    private static byte[] unsigned32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    /** Swaps the signature's meaning by flipping a byte in the signed data's clientDataJSON. */
    static String tamper(String responseJson) throws Exception {
        ObjectNode credential = (ObjectNode) JSON.readTree(responseJson);
        ObjectNode response = (ObjectNode) credential.get("response");
        byte[] signature = Base64.getUrlDecoder().decode(response.get("signature").asText());
        byte[] copy = Arrays.copyOf(signature, signature.length);
        copy[copy.length - 1] ^= 0x01;
        response.put("signature", B64.encodeToString(copy));
        return credential.toString();
    }
}
