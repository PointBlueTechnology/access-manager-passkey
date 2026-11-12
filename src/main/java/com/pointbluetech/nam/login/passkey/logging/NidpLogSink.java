package com.pointbluetech.nam.login.passkey.logging;

import java.util.logging.Level;

/**
 * Destination for log records produced through SLF4J (the Yubico library and anything else
 * bundled in this jar). Production uses {@link NidpAppLogSink}; tests substitute a capturing sink.
 *
 * Only {@link Level#FINE}, {@link Level#INFO}, {@link Level#WARNING} and {@link Level#SEVERE}
 * are ever passed in.
 */
public interface NidpLogSink {

    /** Logs nothing: for builds and tests without the Identity Server's NIDPLog. */
    NidpLogSink NONE = new NidpLogSink() {
        @Override
        public boolean isEnabled(Level level) {
            return false;
        }

        @Override
        public void log(Level level, String message, Throwable throwable) {
        }
    };

    boolean isEnabled(Level level);

    void log(Level level, String message, Throwable throwable);
}
