package com.pointbluetech.nam.login.passkey;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Emails users about changes to their passkeys without ever making a request wait. A request only
 * adds the message to a small queue in memory; one background thread looks up the address and
 * sends. When the queue is full the message is dropped and logged rather than holding anyone up,
 * and the queue doesn't survive a restart. Messages never include a recovery code or helpdesk token;
 * the only code ever sent is a first-passkey setup code, to the user who asked for it.
 */
final class Notifier {

    static final int QUEUE_CAPACITY = 100;
    private static final int MAX_RECIPIENTS = 5;
    private static final Pattern ADDRESS = Pattern.compile("^[^@\\s]+@[^@\\s]+$");
    private static final Pattern LOGGED_ADDRESS = Pattern.compile("[^@\\s<>\"',;:()\\[\\]]+@([A-Za-z0-9.-]+)");

    /** Where to send; runs on the notification thread, so a slow directory holds up nobody. */
    interface Recipients {
        List<String> lookup();
    }

    interface Log {
        default void fine(String message) {
        }

        void info(String message);

        void warning(String message);
    }

    /** One message, ready to send. */
    static final class Message {
        final String subject;
        final String text;
        final String html;

        Message(String subject, String text, String html) {
            this.subject = subject;
            this.text = text;
            this.html = html;
        }
    }

    private final Executor executor;
    private final Supplier<MailSender> senderFactory;
    private final Log log;
    private final AtomicBoolean reportedUnconfigured = new AtomicBoolean();
    private volatile MailSender sender;
    private volatile boolean senderUnavailable;

    Notifier(Executor executor, Supplier<MailSender> senderFactory, Log log) {
        this.executor = executor;
        this.senderFactory = senderFactory;
        this.log = log;
    }

    /** One daemon thread, started on first use and stopped when idle, with a bounded queue. */
    static ThreadPoolExecutor newMailThread() {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1, 60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(QUEUE_CAPACITY), runnable -> {
                    Thread thread = new Thread(runnable, "passkey-notifications");
                    thread.setDaemon(true);
                    return thread;
                }, new ThreadPoolExecutor.AbortPolicy());
        executor.allowCoreThreadTimeOut(true);
        return executor;
    }

    /** NAM's own sender, loaded by name so a NAM version without its email client can't break the class. */
    static MailSender namSender() {
        try {
            return (MailSender) Class.forName("com.pointbluetech.nam.login.passkey.NamMailSender")
                    .getDeclaredConstructor().newInstance();
        } catch (ReflectiveOperationException | LinkageError e) {
            throw new IllegalStateException("NAM's email client isn't available: " + e, e);
        }
    }

    /**
     * Queues a message and returns at once. Never throws: a notification must not break the change
     * it reports.
     *
     * @param user who it's about, for the log; the address itself is never logged
     * @param values filled into the message: name, time, ip
     */
    void submit(Notification event, String user, Recipients recipients, Map<String, String> values, Locale locale) {
        try {
            executor.execute(() -> deliver(event, user, recipients, values, locale));
        } catch (RejectedExecutionException e) {
            log.warning("Dropped the '" + event.key + "' email for " + user + ": the notification queue is full");
        } catch (RuntimeException e) {
            log.warning("Couldn't queue the '" + event.key + "' email for " + user + ": " + withoutAddresses(e.toString()));
        }
    }

    private void deliver(Notification event, String user, Recipients recipients, Map<String, String> values,
            Locale locale) {
        try {
            MailSender mail = sender();
            if (mail == null) {
                return;
            }
            if (!mail.isConfigured()) {
                String why = mail.status();
                if (reportedUnconfigured.compareAndSet(false, true)) {
                    log.info("Passkey emails are on, but skipping them: " + why);
                }
                log.fine("Skipped the '" + event.key + "' email for " + user + ": " + why);
                return;
            }
            reportedUnconfigured.set(false);
            List<String> to = addresses(recipients.lookup());
            if (to.isEmpty()) {
                log.info("No email address for " + user + "; skipped the '" + event.key + "' email");
                return;
            }
            Message message = compose(event, values, locale);
            mail.send(to, message.subject, message.text, message.html);
            log.info("Sent the '" + event.key + "' email for " + user);
        } catch (Exception | LinkageError e) {
            log.warning("Couldn't send the '" + event.key + "' email for " + user + ": " + withoutAddresses(e.toString()));
        }
    }

    /** Whether a message queued now would be sent, for flows that tell the user to look for it. */
    boolean ready() {
        try {
            MailSender mail = sender();
            return mail != null && mail.isConfigured();
        } catch (RuntimeException | LinkageError e) {
            return false;
        }
    }

    private MailSender sender() {
        if (sender == null && !senderUnavailable) {
            try {
                sender = senderFactory.get();
            } catch (RuntimeException | LinkageError e) {
                senderUnavailable = true;
                log.warning("Passkey emails are off: " + e.getMessage());
            }
        }
        return sender;
    }

    /** Plausible, distinct addresses only; anything that could carry a header break is dropped. */
    static List<String> addresses(List<String> values) {
        Set<String> found = new LinkedHashSet<>();
        for (String value : values) {
            String address = value == null ? "" : value.trim();
            if (ADDRESS.matcher(address).matches() && found.size() < MAX_RECIPIENTS) {
                found.add(address);
            }
        }
        return new ArrayList<>(found);
    }

    /** A mail error can name the recipient; the log keeps only the domain. */
    static String withoutAddresses(String text) {
        return text == null ? null : LOGGED_ADDRESS.matcher(text).replaceAll("•••@$1");
    }

    static Message compose(Notification event, Map<String, String> values, Locale locale) {
        String subject = PasskeyMessages.get(locale, "notify." + event.key + ".subject");
        String body = PasskeyMessages.get(locale, "notify." + event.key + ".body");
        String footer = PasskeyMessages.get(locale, "notify.footer");
        String text = fill(body, values, false) + "\n\n" + footer;
        String html = "<p>" + fill(escape(body), values, true) + "</p>\n<p>" + escape(footer) + "</p>";
        return new Message(subject, text, html);
    }

    private static String fill(String template, Map<String, String> values, boolean html) {
        String result = template;
        for (String key : new String[] {"name", "time", "ip", "code"}) {
            String value = values.getOrDefault(key, "");
            // A passkey name is the user's own text; keep it to one plain line
            value = value.replaceAll("[\\r\\n\\t]+", " ").trim();
            result = result.replace("{" + key + "}", html ? escape(value) : value);
        }
        return result;
    }

    static String escape(String text) {
        StringBuilder out = new StringBuilder(text.length());
        for (char c : text.toCharArray()) {
            switch (c) {
                case '<': out.append("&lt;"); break;
                case '>': out.append("&gt;"); break;
                case '&': out.append("&amp;"); break;
                case '"': out.append("&quot;"); break;
                case '\'': out.append("&#39;"); break;
                default: out.append(c);
            }
        }
        return out.toString();
    }
}
