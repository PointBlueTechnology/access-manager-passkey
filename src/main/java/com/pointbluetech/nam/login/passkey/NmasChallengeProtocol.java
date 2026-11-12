package com.pointbluetech.nam.login.passkey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The client side of eDirectory's NMAS Challenge Response login method (method 31), as carried
 * inside an NMAS login. Five messages, all big-endian:
 * <ol>
 * <li>client: version (short major, short minor), status (int)</li>
 * <li>server: version, status, then if it's 0: digest algorithm (int), HMAC types (int), server
 * nonce (int length + bytes), and the questions it picked (int count, then int length + UTF-8)</li>
 * <li>client: status, HMAC type (int, 256 = HMAC-SHA1), client nonce (int length + bytes)</li>
 * <li>client, for each question in turn: status, proof (int length + bytes), where the proof is
 * HMAC-SHA1 keyed with the lower-cased answer over the client nonce then the server nonce</li>
 * <li>server, after each proof: status, then if it's 0 a server proof (int length + bytes)</li>
 * </ol>
 * The answer itself never leaves the IDP. This has no NMAS or LDAP dependencies, so it can be
 * tested on its own.
 */
final class NmasChallengeProtocol {

    static final int METHOD_ID = 31;
    static final int MAJOR_VERSION = 0;
    static final int MINOR_VERSION = 1;
    static final int HMAC_SHA1 = 256;
    static final int NONCE_BYTES = 48;

    /** Generous bounds on what a server sends, so a broken reply can't make us allocate much. */
    private static final int MAX_QUESTIONS = 64;
    private static final int MAX_FIELD_BYTES = 16 * 1024;

    private static final SecureRandom RANDOM = new SecureRandom();

    private NmasChallengeProtocol() {
    }

    /** What the server sent in its first reply. */
    static final class Challenge {
        final int status;
        final byte[] serverNonce;
        final List<String> questions;

        Challenge(int status, byte[] serverNonce, List<String> questions) {
            this.status = status;
            this.serverNonce = serverNonce;
            this.questions = Collections.unmodifiableList(questions);
        }
    }

    /** The NMAS login's channel to the server, as the module sees it. */
    interface Wire {
        int write(byte[] message) throws Exception;

        byte[] read() throws Exception;
    }

    /** Shows the questions and returns the user's answers, or empty if there aren't any. */
    interface Asker {
        Optional<List<String>> ask(List<String> questions) throws Exception;
    }

    /**
     * Runs the method's exchange: returns 0 when the server accepted every answer, otherwise the
     * server's status or the step's failure. Every answer is sent even when the user left one
     * blank, so a wrong answer takes as long as a right one up to the point the server stops.
     */
    static int exchange(Wire wire, Asker asker) throws Exception {
        int status = wire.write(hello(0));
        Challenge challenge = readChallenge(wire.read());
        if (challenge.status != 0) {
            return challenge.status;
        }
        if (challenge.questions.isEmpty()) {
            throw new IOException("The server asked no questions");
        }
        Optional<List<String>> answers = asker.ask(challenge.questions);
        if (!answers.isPresent()) {
            return NmasCheck.CANCELLED;
        }
        byte[] nonce = newNonce();
        status = wire.write(clientNonce(status, nonce));
        for (int i = 0; i < challenge.questions.size(); i++) {
            String answer = i < answers.get().size() ? answers.get().get(i) : null;
            status = wire.write(clientProof(status, proof(answer, nonce, challenge.serverNonce)));
            int verdict = readServerProof(wire.read());
            if (verdict != 0) {
                return verdict;
            }
        }
        return status;
    }

    static byte[] hello(int status) {
        return write(out -> {
            out.writeShort(MAJOR_VERSION);
            out.writeShort(MINOR_VERSION);
            out.writeInt(status);
        });
    }

    static Challenge readChallenge(byte[] message) throws IOException {
        DataInputStream in = reader(message);
        in.readShort();
        in.readShort();
        int status = in.readInt();
        if (status != 0) {
            return new Challenge(status, new byte[0], new ArrayList<>());
        }
        in.readInt(); // digest algorithm
        in.readInt(); // HMAC types the server takes
        byte[] serverNonce = field(in);
        int count = in.readInt();
        if (count < 0 || count > MAX_QUESTIONS) {
            throw new IOException("Unexpected question count " + count);
        }
        List<String> questions = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            questions.add(new String(field(in), StandardCharsets.UTF_8));
        }
        return new Challenge(status, serverNonce, questions);
    }

    static byte[] newNonce() {
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);
        return nonce;
    }

    static byte[] clientNonce(int status, byte[] clientNonce) {
        return write(out -> {
            out.writeInt(status);
            out.writeInt(HMAC_SHA1);
            out.writeInt(clientNonce.length);
            out.write(clientNonce);
        });
    }

    /**
     * HMAC-SHA1 keyed with the answer, trimmed and lower-cased as NMAS stores it, over the client
     * nonce then the server nonce. A blank answer gets a random key, so it's simply wrong: the
     * exchange goes on the same way rather than stopping early.
     */
    static byte[] proof(String answer, byte[] clientNonce, byte[] serverNonce) {
        String normalized = answer == null ? "" : answer.trim().toLowerCase(Locale.ROOT);
        byte[] key = normalized.isEmpty() ? newNonce() : normalized.getBytes(StandardCharsets.UTF_8);
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            mac.update(clientNonce);
            return mac.doFinal(serverNonce);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA1 is unavailable", e);
        }
    }

    static byte[] clientProof(int status, byte[] proof) {
        return write(out -> {
            out.writeInt(status);
            out.writeInt(proof.length);
            out.write(proof);
        });
    }

    /** The status the server gave a proof: 0 if the answer was right. */
    static int readServerProof(byte[] message) throws IOException {
        if (message == null || message.length < 4) {
            throw new IOException("Empty reply to an answer");
        }
        return reader(message).readInt();
    }

    private interface Body {
        void write(DataOutputStream out) throws IOException;
    }

    private static byte[] write(Body body) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            body.write(out);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return bytes.toByteArray();
    }

    private static DataInputStream reader(byte[] message) throws IOException {
        if (message == null) {
            throw new IOException("No reply from the server");
        }
        return new DataInputStream(new ByteArrayInputStream(message));
    }

    private static byte[] field(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > MAX_FIELD_BYTES) {
            throw new IOException("Unexpected field length " + length);
        }
        byte[] value = new byte[length];
        in.readFully(value);
        return value;
    }
}
