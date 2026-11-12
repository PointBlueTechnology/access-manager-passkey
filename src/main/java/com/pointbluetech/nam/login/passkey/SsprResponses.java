package com.pointbluetech.nam.login.passkey;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/**
 * A user's challenge-response answers as SSPR (Self Service Password Reset, formerly PWM) stores
 * them in an LDAP attribute: a record {@code 0002#guid1#guid2#} followed by an XML response set,
 * each answer hashed in one of SSPR's formats. Written from SSPR's documented storage format, so it
 * checks answers without SSPR running. Helpdesk answers and NMAS-stored answers aren't handled here.
 */
final class SsprResponses {

    static final String RECORD_TYPE = "0002";

    /** One stored question and its hashed answer. */
    static final class Response {
        final String question;
        final boolean required;
        final String format;
        final String salt;
        final int hashCount;
        final String stored;

        Response(String question, boolean required, String format, String salt, int hashCount, String stored) {
            this.question = question;
            this.required = required;
            this.format = format;
            this.salt = salt;
            this.hashCount = hashCount;
            this.stored = stored;
        }
    }

    final List<Response> responses;
    final int minRandomRequired;
    final boolean caseInsensitive;
    /** Identifies this exact stored value, so a check can tell if it changed between asking and answering. */
    final String fingerprint;

    private SsprResponses(List<Response> responses, int minRandomRequired, boolean caseInsensitive, String fingerprint) {
        this.responses = Collections.unmodifiableList(responses);
        this.minRandomRequired = minRandomRequired;
        this.caseInsensitive = caseInsensitive;
        this.fingerprint = fingerprint;
    }

    /** The first stored response record among the attribute's values, if any. */
    static Optional<SsprResponses> from(List<String> values) {
        for (String value : values) {
            if (value != null && value.startsWith(RECORD_TYPE + "#")) {
                return Optional.of(parse(value));
            }
        }
        return Optional.empty();
    }

    /** @throws IllegalArgumentException if the value isn't a readable SSPR response record */
    static SsprResponses parse(String record) {
        // type # guid1 # guid2 # payload, where an empty guid is "."
        String[] parts = record.split("#", 4);
        if (parts.length != 4 || !RECORD_TYPE.equals(parts[0])) {
            throw new IllegalArgumentException("Not an SSPR response record");
        }
        try {
            Element root = xml(parts[3]).getDocumentElement();
            if (!"ResponseSet".equals(root.getTagName())) {
                throw new IllegalArgumentException("Not an SSPR response set");
            }
            List<Response> responses = new ArrayList<>();
            NodeList nodes = root.getChildNodes();
            for (int i = 0; i < nodes.getLength(); i++) {
                Node node = nodes.item(i);
                // helpdesk-response entries are for agents to read, not for the user to answer
                if (node instanceof Element && "response".equals(((Element) node).getTagName())) {
                    responses.add(response((Element) node));
                }
            }
            return new SsprResponses(responses, integer(root.getAttribute("minRandomRequired"), 0),
                    Boolean.parseBoolean(root.getAttribute("caseInsensitive")), sha256(record));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Unreadable SSPR response set: " + e.getMessage(), e);
        }
    }

    private static Response response(Element element) {
        Element challenge = child(element, "challenge");
        Element answer = child(element, "answer");
        if (challenge == null || answer == null) {
            throw new IllegalArgumentException("SSPR response without a challenge or answer");
        }
        String format = answer.getAttribute("format");
        return new Response(challenge.getTextContent(), Boolean.parseBoolean(element.getAttribute("required")),
                format.isEmpty() ? "TEXT" : format.toUpperCase(Locale.ROOT), answer.getAttribute("salt"),
                integer(answer.getAttribute("hashcount"), 1), answer.getTextContent());
    }

    /** The indexes of the required responses, then of the random ones. */
    List<Integer> required() {
        List<Integer> indexes = new ArrayList<>();
        for (int i = 0; i < responses.size(); i++) {
            if (responses.get(i).required) {
                indexes.add(i);
            }
        }
        return indexes;
    }

    List<Integer> random() {
        List<Integer> indexes = new ArrayList<>();
        for (int i = 0; i < responses.size(); i++) {
            if (!responses.get(i).required) {
                indexes.add(i);
            }
        }
        return indexes;
    }

    /**
     * Whether the input answers the stored response, the way SSPR checks it: trimmed, lower-cased
     * when the set is case-insensitive, then compared or hashed in the stored format.
     */
    boolean matches(Response response, String input) {
        if (input == null) {
            return false;
        }
        String answer = input.trim();
        if (answer.isEmpty()) {
            return false;
        }
        if (caseInsensitive) {
            answer = answer.toLowerCase(Locale.ROOT);
        }
        switch (response.format) {
            case "TEXT":
                return caseInsensitive ? sameIgnoringCase(response.stored, answer) : same(response.stored, answer);
            case "MD5":
                return saltedDigest(response, answer, "MD5");
            case "SHA1":
            case "SHA1_SALT":
                return saltedDigest(response, answer, "SHA-1");
            case "SHA256_SALT":
                return saltedDigest(response, answer, "SHA-256");
            case "SHA512_SALT":
                return saltedDigest(response, answer, "SHA-512");
            case "PBKDF2":
                return pbkdf2(response, answer, "PBKDF2WithHmacSHA1", 512);
            case "PBKDF2_SHA256":
                return pbkdf2(response, answer, "PBKDF2WithHmacSHA256", 1024);
            case "PBKDF2_SHA512":
                return pbkdf2(response, answer, "PBKDF2WithHmacSHA512", 1536);
            case "BCRYPT":
            case "SCRYPT":
                try {
                    return "BCRYPT".equals(response.format)
                            ? SsprCrypt.bcrypt(response.stored, answer)
                            : SsprCrypt.scrypt(response.stored, answer);
                } catch (LinkageError e) {
                    // BouncyCastle isn't on this server
                    return false;
                }
            default:
                // HELPDESK and NMAS answers can't be checked here
                return false;
        }
    }

    /**
     * Version B ("B:hash") digests salt + answer hashcount times; version A (no prefix, or "A:")
     * digests it once. The result is base64.
     */
    private static boolean saltedDigest(Response response, String answer, String algorithm) {
        String stored = response.stored.trim();
        boolean versionB = stored.startsWith("B:");
        if (versionB || stored.startsWith("A:")) {
            stored = stored.substring(2);
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] bytes = (response.salt + answer).getBytes(StandardCharsets.UTF_8);
            int rounds = versionB ? Math.max(1, response.hashCount) : 1;
            for (int i = 0; i < rounds; i++) {
                bytes = digest.digest(bytes);
            }
            return sameIgnoringCase(stored, Base64.getEncoder().encodeToString(bytes));
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static boolean pbkdf2(Response response, String answer, String algorithm, int bits) {
        try {
            PBEKeySpec spec = new PBEKeySpec(answer.toCharArray(), response.salt.getBytes(StandardCharsets.UTF_8),
                    Math.max(1, response.hashCount), bits);
            byte[] key = SecretKeyFactory.getInstance(algorithm).generateSecret(spec).getEncoded();
            spec.clearPassword();
            return sameIgnoringCase(response.stored.trim(), Base64.getEncoder().encodeToString(key));
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** SSPR compares hashes ignoring case; the time taken doesn't depend on where they differ. */
    private static boolean sameIgnoringCase(String a, String b) {
        return same(a.toLowerCase(Locale.ROOT), b.toLowerCase(Locale.ROOT));
    }

    private static boolean same(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static Document xml(String text) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Stored data from the directory: no DTDs, no external entities
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setErrorHandler(null);
        return builder.parse(new InputSource(new StringReader(text)));
    }

    private static Element child(Element parent, String name) {
        NodeList nodes = parent.getElementsByTagName(name);
        return nodes.getLength() == 0 ? null : (Element) nodes.item(0);
    }

    private static int integer(String value, int fallback) {
        try {
            return value == null || value.isEmpty() ? fallback : Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static String sha256(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
