package com.pointbluetech.nam.login.passkey;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Remembers, for a while, that the user store's proxy account may read an attribute, so that each
 * passkey-only sign-in doesn't ask eDirectory again. The answer is kept per container: the proxy's
 * rights normally come from ACLs on the containers above the users, so users in one container share
 * them. Only a confirmed "may read" is kept. A refusal or a failed check is asked again every time,
 * so a fixed ACL takes effect at the next sign-in.
 */
final class ReadRightsCache {

    private final Clock clock;
    private final int maxEntries;
    private final Map<String, Long> confirmedUntil = new ConcurrentHashMap<>();

    ReadRightsCache(Clock clock, int maxEntries) {
        this.clock = clock;
        this.maxEntries = maxEntries;
    }

    /**
     * @param scope the proxy account and container the answer holds for
     * @param ttlSec how long a confirmed answer is kept; 0 asks every time
     * @param check asks the directory
     */
    AccountRestrictions.ReadRights cached(String scope, long ttlSec, AccountRestrictions.ReadRights check) {
        return attribute -> {
            String key = scope + '\n' + attribute;
            long now = clock.millis();
            Long until = confirmedUntil.get(key);
            if (until != null && now < until) {
                return true;
            }
            boolean readable = check.canRead(attribute);
            if (!readable || ttlSec <= 0) {
                confirmedUntil.remove(key);
            } else {
                if (confirmedUntil.size() >= maxEntries) {
                    // Many containers: start afresh rather than track ages
                    confirmedUntil.clear();
                }
                confirmedUntil.put(key, now + ttlSec * 1000);
            }
            return readable;
        };
    }
}
