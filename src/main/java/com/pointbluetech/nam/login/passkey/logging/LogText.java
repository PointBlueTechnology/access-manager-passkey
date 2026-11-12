package com.pointbluetech.nam.login.passkey.logging;

/**
 * Makes a message safe to write to the IDP log. Some messages carry text the client chose (a
 * request parameter, the origin in a passkey response, a token from a malformed request), and a
 * line break or a {@code </amLogEntry>} in it could fake a log entry. Line breaks and other control
 * characters become visible escapes, angle brackets become look-alikes, and very long messages are cut.
 */
public final class LogText {

    static final int MAX_LENGTH = 4000;

    private LogText() {
    }

    public static String clean(String message) {
        if (message == null) {
            return "null";
        }
        int length = Math.min(message.length(), MAX_LENGTH);
        StringBuilder out = new StringBuilder(length + 16);
        for (int i = 0; i < length; i++) {
            char c = message.charAt(i);
            switch (c) {
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                case '<':
                    out.append('‹');
                    break;
                case '>':
                    out.append('›');
                    break;
                default:
                    if (Character.isISOControl(c) || c == ' ' || c == ' ') {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        if (message.length() > MAX_LENGTH) {
            out.append("... (").append(message.length() - MAX_LENGTH).append(" more characters)");
        }
        return out.toString();
    }
}
