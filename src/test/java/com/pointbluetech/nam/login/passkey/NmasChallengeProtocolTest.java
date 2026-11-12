package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

/**
 * The challenge-response exchange against a fake eDirectory that plays the server's side of the
 * protocol and checks each proof against answers it knows.
 */
class NmasChallengeProtocolTest {

    private static final int WRONG = -1697;

    /** The server side: sends the questions, then checks each proof in turn, stopping at a wrong one. */
    private static final class FakeServer implements NmasChallengeProtocol.Wire {
        final Map<String, String> answers = new LinkedHashMap<>();
        final byte[] serverNonce = NmasChallengeProtocol.newNonce();
        final Deque<byte[]> replies = new ArrayDeque<>();
        final List<byte[]> received = new ArrayList<>();
        int challengeStatus;
        byte[] clientNonce;
        int proofsChecked;

        FakeServer answer(String question, String answer) {
            answers.put(question, answer);
            return this;
        }

        @Override
        public int write(byte[] message) throws IOException {
            received.add(message);
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(message));
            if (received.size() == 1) {
                assertEquals(NmasChallengeProtocol.MAJOR_VERSION, in.readShort());
                assertEquals(NmasChallengeProtocol.MINOR_VERSION, in.readShort());
                assertEquals(0, in.readInt());
                replies.add(challenge());
            } else if (received.size() == 2) {
                assertEquals(0, in.readInt());
                assertEquals(NmasChallengeProtocol.HMAC_SHA1, in.readInt());
                clientNonce = new byte[in.readInt()];
                in.readFully(clientNonce);
            } else {
                assertEquals(0, in.readInt());
                byte[] proof = new byte[in.readInt()];
                in.readFully(proof);
                String expected = new ArrayList<>(answers.values()).get(proofsChecked++);
                boolean right = Arrays.equals(proof, hmac(expected, clientNonce, serverNonce));
                replies.add(serverProof(right ? 0 : WRONG));
            }
            return 0;
        }

        @Override
        public byte[] read() {
            return replies.poll();
        }

        private byte[] challenge() throws IOException {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeShort(0);
            out.writeShort(1);
            out.writeInt(challengeStatus);
            if (challengeStatus == 0) {
                out.writeInt(1);
                out.writeInt(NmasChallengeProtocol.HMAC_SHA1);
                out.writeInt(serverNonce.length);
                out.write(serverNonce);
                out.writeInt(answers.size());
                for (String question : answers.keySet()) {
                    byte[] text = question.getBytes(StandardCharsets.UTF_8);
                    out.writeInt(text.length);
                    out.write(text);
                }
            }
            return bytes.toByteArray();
        }

        private static byte[] serverProof(int status) throws IOException {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeInt(status);
            if (status == 0) {
                out.writeInt(20);
                out.write(new byte[20]);
            }
            return bytes.toByteArray();
        }
    }

    /** As the stored answer is keyed on the server: lower-cased. */
    private static byte[] hmac(String answer, byte[] clientNonce, byte[] serverNonce) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(answer.toLowerCase().getBytes(StandardCharsets.UTF_8), "HmacSHA1"));
            mac.update(clientNonce);
            return mac.doFinal(serverNonce);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte b : bytes) {
            out.append(String.format("%02x", b));
        }
        return out.toString();
    }

    private static FakeServer server() {
        return new FakeServer()
                .answer("First pet?", "Blue Kestrel")
                .answer("Street?", "Seven Oaks")
                .answer("Teacher?", "Mrs Ávila");
    }

    private static NmasChallengeProtocol.Asker answering(String... answers) {
        return questions -> Optional.of(Arrays.asList(answers));
    }

    @Test
    void proofMatchesAnIndependentHmac() {
        byte[] clientNonce = new byte[48];
        byte[] serverNonce = new byte[48];
        for (int i = 0; i < 48; i++) {
            clientNonce[i] = (byte) i;
            serverNonce[i] = (byte) (48 + i);
        }
        // Computed with Python's hmac module
        assertEquals("9f0783dc5f7d609e09c350ef04e56f806e0767f2",
                hex(NmasChallengeProtocol.proof("  Blue KESTREL ", clientNonce, serverNonce)));
        assertEquals("602e866b8519c0adfbab29d995906f484c4396c0",
                hex(NmasChallengeProtocol.proof("ÁVILA", clientNonce, serverNonce)));
    }

    @Test
    void messagesHaveTheMethodsLayout() {
        assertArrayEquals(new byte[] {0, 0, 0, 1, 0, 0, 0, 0}, NmasChallengeProtocol.hello(0));
        byte[] nonce = {9, 8, 7};
        assertArrayEquals(new byte[] {0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 3, 9, 8, 7},
                NmasChallengeProtocol.clientNonce(0, nonce));
        assertArrayEquals(new byte[] {0, 0, 0, 0, 0, 0, 0, 2, 5, 6}, NmasChallengeProtocol.clientProof(0, new byte[] {5, 6}));
    }

    @Test
    void rightAnswersPass() throws Exception {
        FakeServer server = server();
        List<String> asked = new ArrayList<>();
        int status = NmasChallengeProtocol.exchange(server, questions -> {
            asked.addAll(questions);
            return Optional.of(Arrays.asList("blue kestrel", " SEVEN OAKS ", "mrs ávila"));
        });
        assertEquals(0, status);
        assertEquals(List.of("First pet?", "Street?", "Teacher?"), asked);
        assertEquals(3, server.proofsChecked);
    }

    @Test
    void aWrongAnswerFailsWithTheServersStatus() throws Exception {
        FakeServer server = server();
        assertEquals(WRONG, NmasChallengeProtocol.exchange(server, answering("Blue Kestrel", "Elm Street", "Mrs Ávila")));
        // The server stops at the first wrong answer
        assertEquals(2, server.proofsChecked);
    }

    @Test
    void blankOrMissingAnswersAreWrongNotErrors() throws Exception {
        assertEquals(WRONG, NmasChallengeProtocol.exchange(server(), answering("   ", "Seven Oaks", "Mrs Ávila")));
        assertEquals(WRONG, NmasChallengeProtocol.exchange(server(), answering("Blue Kestrel")));
    }

    @Test
    void noAnswersCancelsBeforeAnyProof() throws Exception {
        FakeServer server = server();
        assertEquals(NmasCheck.CANCELLED, NmasChallengeProtocol.exchange(server, questions -> Optional.empty()));
        assertEquals(1, server.received.size());
    }

    @Test
    void aServerRefusalComesBackWithoutAsking() throws Exception {
        FakeServer server = server();
        server.challengeStatus = -1664;
        boolean[] asked = {false};
        assertEquals(-1664, NmasChallengeProtocol.exchange(server, questions -> {
            asked[0] = true;
            return Optional.of(List.of());
        }));
        assertFalse(asked[0]);
    }

    @Test
    void refusesBrokenReplies() throws IOException {
        byte[] hugeCount = {0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0x7f, 0, 0, 0};
        assertThrows(IOException.class, () -> NmasChallengeProtocol.readChallenge(hugeCount));
        assertThrows(IOException.class, () -> NmasChallengeProtocol.readChallenge(new byte[] {0, 0, 0, 1, 0, 0}));
        assertThrows(IOException.class, () -> NmasChallengeProtocol.readChallenge(null));
        assertThrows(IOException.class, () -> NmasChallengeProtocol.readServerProof(new byte[0]));
        assertTrue(NmasChallengeProtocol.readChallenge(new byte[] {0, 0, 0, 1, -1, -1, -7, -112}).questions.isEmpty());
    }
}
