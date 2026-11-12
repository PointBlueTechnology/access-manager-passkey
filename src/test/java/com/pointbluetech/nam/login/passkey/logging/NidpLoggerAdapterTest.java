package com.pointbluetech.nam.login.passkey.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.logging.Level;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class NidpLoggerAdapterTest {

    @AfterEach
    void restoreSink() {
        NidpLoggerFactory.resetSink();
    }

    @Test
    void slf4jBindsToOurFactory() {
        Logger logger = LoggerFactory.getLogger("com.yubico.webauthn.RelyingParty");
        assertInstanceOf(NidpLoggerAdapter.class, logger);
        assertInstanceOf(NidpLoggerFactory.class, LoggerFactory.getILoggerFactory());
    }

    @Test
    void mapsSlf4jLevelsToNidpLevels() {
        CapturingSink sink = new CapturingSink(Level.FINE);
        NidpLoggerFactory.setSink(sink);
        Logger logger = LoggerFactory.getLogger("com.yubico.webauthn.RelyingParty");

        logger.trace("t");
        logger.debug("d");
        logger.info("i");
        logger.warn("w");
        logger.error("e");

        List<CapturingSink.Entry> entries = sink.entries();
        assertEquals(5, entries.size());
        assertEquals(Level.FINE, entries.get(0).level);
        assertEquals(Level.FINE, entries.get(1).level);
        assertEquals(Level.INFO, entries.get(2).level);
        assertEquals(Level.WARNING, entries.get(3).level);
        assertEquals(Level.SEVERE, entries.get(4).level);
        assertEquals("[Passkey:RelyingParty] e", entries.get(4).message);
    }

    @Test
    void respectsNamLevelAndSkipsFormattingWhenDisabled() {
        CapturingSink sink = new CapturingSink(Level.WARNING);
        NidpLoggerFactory.setSink(sink);
        Logger logger = LoggerFactory.getLogger("x.Y");

        assertFalse(logger.isDebugEnabled());
        assertFalse(logger.isInfoEnabled());
        assertTrue(logger.isWarnEnabled());

        Object explodes = new Object() {
            @Override
            public String toString() {
                throw new AssertionError("argument formatted although level is disabled");
            }
        };
        logger.debug("value {}", explodes);
        logger.warn("kept");

        assertEquals(1, sink.entries().size());
        assertEquals("[Passkey:Y] kept", sink.entries().get(0).message);
    }

    @Test
    void formatsPlaceholdersAndExtractsTrailingThrowable() {
        CapturingSink sink = new CapturingSink(Level.FINE);
        NidpLoggerFactory.setSink(sink);
        Logger logger = LoggerFactory.getLogger("a.B");
        IllegalStateException boom = new IllegalStateException("boom");

        logger.warn("one {} two {}", "x", "y");
        logger.error("failed for {}", "alice", boom);
        logger.info("plain", boom);

        List<CapturingSink.Entry> entries = sink.entries();
        assertEquals("[Passkey:B] one x two y", entries.get(0).message);
        assertNull(entries.get(0).throwable);
        assertEquals("[Passkey:B] failed for alice", entries.get(1).message);
        assertSame(boom, entries.get(1).throwable);
        assertSame(boom, entries.get(2).throwable);
    }

    @Test
    void sinkChangeAppliesToLoggersAlreadyHandedOut() {
        Logger early = LoggerFactory.getLogger("early.Logger");
        CapturingSink sink = new CapturingSink(Level.FINE);
        NidpLoggerFactory.setSink(sink);

        early.info("after swap");

        assertEquals(1, sink.entries().size());
    }

    @Test
    void simpleNameHandlesEdgeCases() {
        assertEquals("root", NidpLoggerAdapter.simpleName(""));
        assertEquals("Plain", NidpLoggerAdapter.simpleName("Plain"));
        assertEquals("C", NidpLoggerAdapter.simpleName("a.b.C"));
    }
}
