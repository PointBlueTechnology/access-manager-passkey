package com.pointbluetech.nam.login.passkey.logging;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;

/**
 * SLF4J logger factory returned by {@code org.slf4j.impl.StaticLoggerBinder}.
 *
 * The sink is looked up on every call, so {@link #setSink(NidpLogSink)} takes effect for
 * loggers that were already handed out (libraries usually hold theirs in static fields).
 */
public final class NidpLoggerFactory implements ILoggerFactory {

    private static volatile NidpLogSink sink = defaultSink();

    private final ConcurrentMap<String, Logger> loggers = new ConcurrentHashMap<>();

    @Override
    public Logger getLogger(String name) {
        return loggers.computeIfAbsent(name, n -> new NidpLoggerAdapter(n, NidpLoggerFactory::sink));
    }

    static NidpLogSink sink() {
        return sink;
    }

    /** Replaces the destination for all loggers. For tests; production keeps the NIDPLog sink. */
    public static void setSink(NidpLogSink newSink) {
        if (newSink == null) {
            throw new IllegalArgumentException("sink must not be null");
        }
        sink = newSink;
    }

    /** Restores the default NIDPLog Application-logger sink. */
    public static void resetSink() {
        sink = defaultSink();
    }

    /**
     * NIDPLog's Application logger, loaded by name, as on the Identity Server. Without NAM's classes,
     * as in a build that has no Identity Server jars to compile against, nothing is logged.
     */
    private static NidpLogSink defaultSink() {
        try {
            return (NidpLogSink) Class.forName("com.pointbluetech.nam.login.passkey.logging.NidpAppLogSink")
                    .getDeclaredConstructor().newInstance();
        } catch (ReflectiveOperationException | LinkageError e) {
            return NidpLogSink.NONE;
        }
    }
}
