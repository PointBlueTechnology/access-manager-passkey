package com.pointbluetech.nam.login.passkey.logging;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;

/** Test sink that records every enabled log call. */
public final class CapturingSink implements NidpLogSink {

    public static final class Entry {
        public final Level level;
        public final String message;
        public final Throwable throwable;

        Entry(Level level, String message, Throwable throwable) {
            this.level = level;
            this.message = message;
            this.throwable = throwable;
        }
    }

    private final Level threshold;
    private final List<Entry> entries = Collections.synchronizedList(new ArrayList<>());

    public CapturingSink(Level threshold) {
        this.threshold = threshold;
    }

    @Override
    public boolean isEnabled(Level level) {
        return level.intValue() >= threshold.intValue();
    }

    @Override
    public void log(Level level, String message, Throwable throwable) {
        entries.add(new Entry(level, message, throwable));
    }

    public List<Entry> entries() {
        synchronized (entries) {
            return new ArrayList<>(entries);
        }
    }
}
