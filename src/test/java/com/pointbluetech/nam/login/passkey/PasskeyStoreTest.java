package com.pointbluetech.nam.login.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class PasskeyStoreTest {

    private static final String ATTR = "pbtPasskeyCredential";
    private static final String GOOD = "v1:{\"id\":\"AQID\",\"pk\":\"BAUG\",\"sc\":5,\"uh\":\"BwgJ\",\"nm\":\"Laptop\","
            + "\"aa\":\"00\",\"tr\":[\"internal\"],\"be\":true,\"bs\":false,\"disc\":true,"
            + "\"cr\":\"2026-11-01T14:03:00Z\"}";
    private static final String FROM_THE_FUTURE = "v2:something-newer";

    private final InMemoryAttributes directory = new InMemoryAttributes();
    private final PasskeyStore store = new PasskeyStore(directory, ATTR, "pbtPasskeyUser");

    @Test
    void noValuesMeansNoPasskeys() {
        assertTrue(store.load().isEmpty());
    }

    @Test
    void recordSurvivesARoundTrip() {
        directory.values.put(ATTR, List.of(GOOD));

        PasskeyRecord record = store.load().get(0);
        assertEquals("Laptop", record.name());
        assertEquals(5, record.signCount());
        assertEquals(GOOD, record.encode());
    }

    @Test
    void valuesWeCannotReadAreSkippedButKeptOnWrite() {
        directory.values.put(ATTR, new ArrayList<>(List.of(GOOD, FROM_THE_FUTURE)));

        assertEquals(1, store.load().size());
        store.update(records -> records);

        assertEquals(2, directory.passkeyValues().size());
        assertTrue(directory.passkeyValues().contains(FROM_THE_FUTURE));
    }

    @Test
    void removingTheLastPasskeyRemovesTheAttribute() {
        directory.values.put(ATTR, new ArrayList<>(List.of(GOOD)));

        store.update(records -> new ArrayList<>());

        assertFalse(directory.values.containsKey(ATTR));
    }

    @Test
    void auxClassIsAddedOnceAndKeepsExistingClasses() {
        directory.values.put(ATTR, new ArrayList<>(List.of(GOOD)));

        store.update(records -> records);
        store.update(records -> records);

        assertEquals(List.of("top", "inetOrgPerson", "pbtPasskeyUser"), directory.values.get("objectClass"));
    }

    @Test
    void auxClassMatchIgnoresCase() {
        directory.values.put(ATTR, new ArrayList<>(List.of(GOOD)));
        directory.values.put("objectClass", new ArrayList<>(List.of("top", "PBTPASSKEYUSER")));

        store.update(records -> records);

        assertEquals(2, directory.values.get("objectClass").size());
    }

    @Test
    void blankAuxClassLeavesObjectClassAlone() {
        directory.values.put(ATTR, new ArrayList<>(List.of(GOOD)));

        new PasskeyStore(directory, ATTR, "").update(records -> records);

        assertEquals(List.of("top", "inetOrgPerson"), directory.values.get("objectClass"));
    }

    @Test
    void refusesToWriteObjectClassWhenItCannotSeeTheCurrentOnes() {
        directory.values.put(ATTR, new ArrayList<>(List.of(GOOD)));
        directory.values.remove("objectClass");

        assertThrows(PasskeyStoreException.class, () -> store.update(records -> records));
        assertEquals(0, directory.writes);
    }

    @Test
    void readFailureStopsTheWrite() {
        directory.values.put(ATTR, new ArrayList<>(List.of(GOOD)));
        directory.readsFail = true;

        assertThrows(PasskeyStoreException.class, () -> store.update(records -> new ArrayList<>()));
        assertEquals(0, directory.writes);
    }
}
