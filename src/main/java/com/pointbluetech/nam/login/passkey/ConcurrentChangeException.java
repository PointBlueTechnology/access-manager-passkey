package com.pointbluetech.nam.login.passkey;

/**
 * The attribute changed between reading it and writing it: a value to remove was already gone, or one
 * to add was already there. Nothing was written.
 */
public class ConcurrentChangeException extends PasskeyStoreException {

    private static final long serialVersionUID = 1L;

    public ConcurrentChangeException(String message, Throwable cause) {
        super(message, cause);
    }
}
