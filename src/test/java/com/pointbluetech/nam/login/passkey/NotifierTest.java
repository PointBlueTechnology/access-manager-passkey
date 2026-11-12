package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class NotifierTest {

    private static final Map<String, String> VALUES =
            Map.of("name", "Work laptop", "time", "2026-11-10 17:30 UTC", "ip", "192.0.2.7");

    private final List<String> infos = Collections.synchronizedList(new ArrayList<>());
    private final List<String> warnings = Collections.synchronizedList(new ArrayList<>());
    private final Notifier.Log log = new Notifier.Log() {
        @Override
        public void info(String message) {
            infos.add(message);
        }

        @Override
        public void warning(String message) {
            warnings.add(message);
        }
    };

    /** Records what would be sent. */
    private static class FakeSender implements MailSender {
        final List<List<String>> to = new ArrayList<>();
        final List<String> subjects = new ArrayList<>();
        final List<String> texts = new ArrayList<>();
        boolean configured = true;

        @Override
        public boolean isConfigured() {
            return configured;
        }

        @Override
        public void send(List<String> recipients, String subject, String text, String html) {
            to.add(recipients);
            subjects.add(subject);
            texts.add(text);
        }
    }

    private Notifier inline(MailSender sender) {
        return new Notifier(Runnable::run, () -> sender, log);
    }

    @Test
    void sendsTheMessageToTheUsersAddress() {
        FakeSender sender = new FakeSender();
        inline(sender).submit(Notification.PASSKEY_ADDED, "cn=u", () -> List.of("u@example.com"), VALUES, Locale.ENGLISH);

        assertEquals(List.of(List.of("u@example.com")), sender.to);
        assertEquals("A passkey was added to your account", sender.subjects.get(0));
        assertTrue(sender.texts.get(0).contains("\"Work laptop\""));
        assertTrue(sender.texts.get(0).contains("192.0.2.7"));
        assertTrue(infos.contains("Sent the 'added' email for cn=u"));
        assertFalse(String.join("\n", infos).contains("u@example.com"), "addresses are not logged");
    }

    @Test
    void aStuckMailServerNeverHoldsUpTheCaller() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        MailSender stuck = new FakeSender() {
            @Override
            public void send(List<String> recipients, String subject, String text, String html) {
                try {
                    release.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        };
        ThreadPoolExecutor thread = Notifier.newMailThread();
        Notifier notifier = new Notifier(thread, () -> stuck, log);
        try {
            long start = System.nanoTime();
            for (int i = 0; i < Notifier.QUEUE_CAPACITY + 10; i++) {
                notifier.submit(Notification.PASSKEY_REMOVED, "cn=u", () -> List.of("u@example.com"), VALUES, Locale.ENGLISH);
            }
            long tookMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

            assertTrue(tookMs < 1000, "submitting took " + tookMs + " ms");
            // One being sent, a full queue behind it, and the rest dropped with a warning each
            assertEquals(9, warnings.stream().filter(w -> w.contains("queue is full")).count());
        } finally {
            release.countDown();
            thread.shutdown();
            thread.awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void nothingIsSentWhileNamEmailIsntSetUpAndThatIsLoggedOnce() {
        FakeSender sender = new FakeSender();
        sender.configured = false;
        Notifier notifier = inline(sender);
        notifier.submit(Notification.CODES_REPLACED, "cn=u", () -> List.of("u@example.com"), VALUES, Locale.ENGLISH);
        notifier.submit(Notification.CODES_REPLACED, "cn=u", () -> List.of("u@example.com"), VALUES, Locale.ENGLISH);

        assertTrue(sender.to.isEmpty());
        assertEquals(1, infos.stream().filter(i -> i.contains("skipping them")).count());

        sender.configured = true;
        notifier.submit(Notification.CODES_REPLACED, "cn=u", () -> List.of("u@example.com"), VALUES, Locale.ENGLISH);
        assertEquals(1, sender.to.size(), "starts sending once it's set up");
    }

    @Test
    void aMissingNamEmailClientTurnsEmailsOffWithoutBreakingAnything() {
        Notifier notifier = new Notifier(Runnable::run, () -> {
            throw new IllegalStateException("NAM's email client isn't available");
        }, log);
        notifier.submit(Notification.PASSKEY_ADDED, "cn=u", () -> List.of("u@example.com"), VALUES, Locale.ENGLISH);
        notifier.submit(Notification.PASSKEY_ADDED, "cn=u", () -> List.of("u@example.com"), VALUES, Locale.ENGLISH);

        assertEquals(1, warnings.size(), "reported once");
    }

    @Test
    void failuresAreLoggedNotThrown() {
        Notifier notifier = inline(new FakeSender() {
            @Override
            public void send(List<String> recipients, String subject, String text, String html) {
                throw new IllegalStateException("connection refused");
            }
        });
        notifier.submit(Notification.PASSKEY_ADDED, "cn=u", () -> List.of("u@example.com"), VALUES, Locale.ENGLISH);
        inline(new FakeSender()).submit(Notification.PASSKEY_ADDED, "cn=u", () -> {
            throw new PasskeyStoreException("directory down");
        }, VALUES, Locale.ENGLISH);

        assertEquals(2, warnings.size());
        assertTrue(warnings.get(0).contains("connection refused"));
    }

    @Test
    void anAccountWithoutAnAddressIsSkipped() {
        FakeSender sender = new FakeSender();
        inline(sender).submit(Notification.PASSKEY_ADDED, "cn=u", List::of, VALUES, Locale.ENGLISH);

        assertTrue(sender.to.isEmpty());
        assertTrue(infos.get(0).contains("No email address for cn=u"));
    }

    @Test
    void onlyPlausibleDistinctAddressesAreUsed() {
        assertEquals(List.of("a@example.com", "b@example.com"), Notifier.addresses(List.of(
                " a@example.com ", "a@example.com", "not an address", "x@example.com\r\nBcc: e@evil.test",
                "b@example.com", "")));
    }

    @Test
    void thePasskeyNameIsEscapedInHtmlAndKeptToOneLine() {
        Notifier.Message message = Notifier.compose(Notification.PASSKEY_ADDED,
                Map.of("name", "<b>Bob's</b>\r\nkey", "time", "t", "ip", "i"), Locale.ENGLISH);

        assertTrue(message.html.contains("&lt;b&gt;Bob&#39;s&lt;/b&gt; key"));
        assertFalse(message.html.contains("<b>"));
        assertTrue(message.text.contains("\"<b>Bob's</b> key\""));
        assertFalse(message.text.contains("\r"));
    }

    @Test
    void everyNotificationHasItsTextAndNoPlaceholderIsLeft() {
        for (Notification event : Notification.values()) {
            Notifier.Message message = Notifier.compose(event, VALUES, Locale.ENGLISH);
            assertFalse(message.subject.startsWith("notify."), event + " has no subject");
            assertFalse(message.text.contains("notify."), event + " has no body");
            assertFalse(message.text.contains("{"), event + " left a placeholder");
        }
    }

    @Test
    void theSetupCodeEmailCarriesTheCode() {
        Notifier.Message message = Notifier.compose(Notification.ENROLL_CODE,
                Map.of("code", "042517", "time", "now", "ip", "10.0.0.1"), Locale.ENGLISH);
        assertTrue(message.text.contains("042517"));
        assertTrue(message.html.contains("042517"));
    }

    @Test
    void mailErrorsDontLogTheAddress() {
        String error = "javax.mail.SendFailedException: Invalid Addresses;\n  nested exception is: 550 5.1.1 <jane.doe+pk@example.com>: Recipient address rejected";
        String logged = Notifier.withoutAddresses(error);
        assertFalse(logged.contains("jane.doe"));
        assertTrue(logged.contains("\u2022\u2022\u2022@example.com"));
        assertTrue(logged.contains("Recipient address rejected"));
    }
}
