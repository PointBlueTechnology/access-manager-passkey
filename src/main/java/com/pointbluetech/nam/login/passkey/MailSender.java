package com.pointbluetech.nam.login.passkey;

import java.util.List;

/** Sends one message. Called only from the notification thread, never while a request waits. */
interface MailSender {

    /** Whether there's anywhere to send mail; checked before each message, so a later setup takes effect. */
    boolean isConfigured();

    /** Why it isn't configured, for the log; never a password. */
    default String status() {
        return isConfigured() ? "configured" : "not configured";
    }

    void send(List<String> recipients, String subject, String text, String html) throws Exception;
}
