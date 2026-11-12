package com.pointbluetech.nam.login.passkey;

/** The directory couldn't be read or written. Sign-in fails closed when this is thrown. */
public class PasskeyStoreException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public PasskeyStoreException(String message) {
        super(message);
    }

    public PasskeyStoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
