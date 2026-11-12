package com.pointbluetech.nam.login.passkey;

import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/** User-facing text from PasskeyMessages*.properties in the jar. Public for the JSPs. */
public final class PasskeyMessages {

    private static final String BUNDLE = "com.pointbluetech.nam.login.passkey.PasskeyMessages";

    private PasskeyMessages() {
    }

    public static String get(Locale locale, String key) {
        try {
            return ResourceBundle.getBundle(BUNDLE, locale == null ? Locale.ROOT : locale).getString(key);
        } catch (MissingResourceException e) {
            return key;
        }
    }

    /**
     * Makes server-built JSON safe inside {@code <script type="application/json">}: the JSON means
     * the same, but nothing in it can close the script element or open a comment.
     */
    public static String jsonForScriptTag(String json) {
        return json.replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026")
                .replace(" ", "\\u2028")
                .replace(" ", "\\u2029");
    }
}
