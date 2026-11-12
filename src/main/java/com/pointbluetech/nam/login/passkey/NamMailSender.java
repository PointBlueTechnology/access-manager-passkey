package com.pointbluetech.nam.login.passkey;

import com.novell.nam.nidp.email.config.EmailConfigurationManager;
import com.novell.nam.nidp.email.config.xml.EmailConfiguration;
import com.novell.nam.nidp.email.core.Mail;
import com.novell.nam.nidp.email.core.client.AsynchronousEmailClient;
import com.novell.nam.nidp.email.core.factory.AsynchronousClientFactory;
import java.util.List;
import javax.mail.Address;
import javax.mail.internet.InternetAddress;

/**
 * Sends through NAM's own email client, so it uses the Administration Console's Email configuration
 * (the one risk-based authentication uses). These are NAM's internal classes, so only this class
 * refers to them, and {@link Notifier} loads it by name: if a NAM version lacks them, emails are
 * skipped instead of the authentication class failing to load.
 *
 * <p>NAM's client sends on the calling thread, and with protocol SMTP sets no timeouts; that's why
 * it's only ever called from the notification thread. It always sends from the configured SMTP user
 * name, whatever sender the message names.
 */
final class NamMailSender implements MailSender {

    @Override
    public boolean isConfigured() {
        EmailConfiguration config = EmailConfigurationManager.getInstance().getEmailConfigObj();
        // NAM's own factory reads the first provider before checking any of this, and throws
        return config != null && config.isEnabled()
                && config.getEmailProviders() != null && !config.getEmailProviders().isEmpty();
    }

    @Override
    public String status() {
        EmailConfiguration config = EmailConfigurationManager.getInstance().getEmailConfigObj();
        if (config == null) {
            return "NAM hasn't loaded an email configuration";
        }
        if (!config.isEnabled()) {
            return "NAM's email configuration has Enabled turned off";
        }
        if (config.getEmailProviders() == null || config.getEmailProviders().isEmpty()) {
            return "NAM's email configuration names no mail server";
        }
        EmailConfiguration.EmailProvider provider = config.getEmailProviders().get(0);
        return "NAM's email configuration: " + provider.getProtocol() + " " + provider.getDomainName() + ":"
                + provider.getPort() + (provider.isStarttlsEnabled() ? " with STARTTLS" : "");
    }

    @Override
    public void send(List<String> recipients, String subject, String text, String html) throws Exception {
        if (!isConfigured()) {
            throw new IllegalStateException("NAM's email configuration is not enabled");
        }
        AsynchronousEmailClient client = new AsynchronousClientFactory().getDefaultEmailClient();
        if (client == null) {
            throw new IllegalStateException("NAM's email configuration is not enabled");
        }
        Address[] to = new Address[recipients.size()];
        for (int i = 0; i < to.length; i++) {
            to[i] = new InternetAddress(recipients.get(i), true);
        }
        Mail mail = new Mail() {
            @Override
            public String getSender() {
                return null;
            }

            @Override
            public Address[] getRecipients() {
                return to;
            }

            @Override
            public String getSubject() {
                return subject;
            }

            @Override
            public String getTextMessage() {
                return text;
            }

            @Override
            public String getHtmlMessage() {
                return html;
            }
        };
        if (!client.sendMailMessage(mail)) {
            throw new IllegalStateException("NAM's email client reported a failure");
        }
    }
}
