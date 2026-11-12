package com.pointbluetech.nam.login.passkey;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.bouncycastle.crypto.generators.SCrypt;

/**
 * SSPR's BCRYPT and SCRYPT answer formats, which need BouncyCastle. The class uses the copy NAM
 * already ships (bcprov in the IDP's WEB-INF/lib) rather than bundling its own, and only this
 * class refers to it: without BouncyCastle, those two formats fail to match and nothing else breaks.
 */
final class SsprCrypt {

    private static final int SCRYPT_KEY_BYTES = 64;

    private SsprCrypt() {
    }

    static boolean bcrypt(String stored, String answer) {
        try {
            return OpenBSDBCrypt.checkPassword(stored.trim(), answer.toCharArray());
        } catch (RuntimeException | LinkageError e) {
            return false;
        }
    }

    /** {@code $s0$<hex: log2(N) << 16 | r << 8 | p>$<base64 salt>$<base64 key>}, with a 64-byte key. */
    static boolean scrypt(String stored, String answer) {
        try {
            String[] parts = stored.trim().split("\\$");
            if (parts.length != 5 || !"s0".equals(parts[1])) {
                return false;
            }
            long params = Long.parseLong(parts[2], 16);
            int logN = (int) (params >> 16 & 0xffff);
            int r = (int) (params >> 8 & 0xff);
            int p = (int) (params & 0xff);
            // Bounds keep a hostile stored value from tying up the thread or memory
            if (logN < 1 || logN > 20 || r < 1 || r > 32 || p < 1 || p > 32) {
                return false;
            }
            byte[] salt = Base64.getDecoder().decode(parts[3]);
            byte[] expected = Base64.getDecoder().decode(parts[4]);
            byte[] actual = SCrypt.generate(answer.getBytes(StandardCharsets.UTF_8), salt, 1 << logN, r, p,
                    SCRYPT_KEY_BYTES);
            return MessageDigest.isEqual(expected, actual);
        } catch (RuntimeException | LinkageError e) {
            return false;
        }
    }
}
