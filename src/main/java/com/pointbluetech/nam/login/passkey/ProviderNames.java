package com.pointbluetech.nam.login.passkey;

import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;
import java.util.Properties;

/** Display names for passkey providers, by AAGUID. Never used to make a security decision. */
final class ProviderNames {

    private static final Properties NAMES = load();

    private ProviderNames() {
    }

    /** @param aaguid hex with no dashes; browsers often report all zeros, which has no name */
    static Optional<String> forAaguid(String aaguid) {
        return aaguid == null ? Optional.empty() : Optional.ofNullable(NAMES.getProperty(aaguid.toLowerCase()));
    }

    private static Properties load() {
        Properties names = new Properties();
        try (InputStream in = ProviderNames.class.getResourceAsStream("aaguid-names.properties")) {
            if (in != null) {
                names.load(in);
            }
        } catch (IOException e) {
            // Only costs the friendly names
        }
        return names;
    }
}
