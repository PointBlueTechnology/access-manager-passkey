package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class PasskeyRecordTest {

    private static final Instant NOW = Instant.parse("2026-11-04T12:00:00Z");
    private static final long DAY = 86_400;

    private static PasskeyRecord record(String lastUsed) {
        return PasskeyRecord.decode("v1:{\"id\":\"AQID\",\"pk\":\"BAUG\",\"sc\":5,\"uh\":\"BwgJ\",\"nm\":\"n\",\"aa\":\"00\","
                + "\"tr\":[],\"be\":true,\"bs\":false,\"cr\":\"2026-11-01T00:00:00Z\""
                + (lastUsed == null ? "" : ",\"lu\":\"" + lastUsed + "\"") + "}");
    }

    @Test
    void rejectsValuesThatAreNotARecord() {
        for (String bad : new String[] {
                null,
                "",
                "{\"id\":\"AQID\"}",
                "v1:not json",
                "v1:{\"pk\":\"BAUG\",\"uh\":\"BwgJ\",\"cr\":\"2026-11-01T00:00:00Z\"}",
                "v1:{\"id\":\"!!\",\"pk\":\"BAUG\",\"uh\":\"BwgJ\",\"cr\":\"2026-11-01T00:00:00Z\"}",
                "v1:{\"id\":\"AQID\",\"pk\":\"BAUG\",\"uh\":\"BwgJ\",\"cr\":\"yesterday\"}",
        }) {
            assertThrows(IllegalArgumentException.class, () -> PasskeyRecord.decode(bad), String.valueOf(bad));
        }
    }

    @Test
    void writesWhenNeverUsed() {
        assertTrue(record(null).usageWriteNeeded(5, false, NOW, DAY));
    }

    @Test
    void skipsWriteWhenNothingChangedRecently() {
        assertFalse(record("2026-11-04T01:00:00Z").usageWriteNeeded(5, false, NOW, DAY));
    }

    @Test
    void writesWhenCounterRisesBackupChangesOrLastUsedIsStale() {
        assertTrue(record("2026-11-04T01:00:00Z").usageWriteNeeded(6, false, NOW, DAY));
        assertTrue(record("2026-11-04T01:00:00Z").usageWriteNeeded(5, true, NOW, DAY));
        assertTrue(record("2026-11-03T12:00:00Z").usageWriteNeeded(5, false, NOW, DAY));
    }
}
