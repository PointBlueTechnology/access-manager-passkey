package com.pointbluetech.nam.login.passkey;

/** A ceremony was refused; {@link #messageKey()} is the text to show the user in PasskeyMessages. */
public class CeremonyFailedException extends Exception {

    private static final long serialVersionUID = 1L;

    private final String messageKey;

    CeremonyFailedException(String messageKey, String detail) {
        super(detail);
        this.messageKey = messageKey;
    }

    CeremonyFailedException(String messageKey, String detail, Throwable cause) {
        super(detail, cause);
        this.messageKey = messageKey;
    }

    public String messageKey() {
        return messageKey;
    }
}
