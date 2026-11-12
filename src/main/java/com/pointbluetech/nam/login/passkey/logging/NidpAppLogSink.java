package com.pointbluetech.nam.login.passkey.logging;

import com.novell.nidp.logging.NIDPLog;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.logging.Level;

/**
 * Writes to the Identity Server "Application" logger, the same one NAM's own authentication
 * classes use. Its level is set in Administration Console under the Identity Server's
 * Component File Logger Levels > Application, and output lands in the IDP catalina.out.
 */
public final class NidpAppLogSink implements NidpLogSink {

    @Override
    public boolean isEnabled(Level level) {
        if (level == Level.SEVERE) {
            return NIDPLog.isLoggableAppSevere();
        }
        if (level == Level.WARNING) {
            return NIDPLog.isLoggableAppWarning();
        }
        if (level == Level.INFO) {
            return NIDPLog.isLoggableAppInfo();
        }
        return NIDPLog.isLoggableAppFine();
    }

    @Override
    public void log(Level level, String raw, Throwable throwable) {
        String message = LogText.clean(raw);
        if (level == Level.SEVERE) {
            // Appends the stack trace when throwable is non-null
            NIDPLog.severe(NIDPLog.getAppLog(), throwable, message);
        } else if (level == Level.WARNING) {
            if (throwable == null) {
                NIDPLog.logAppWarning(message);
            } else {
                NIDPLog.logAppWarning(throwable, message);
            }
        } else if (level == Level.INFO) {
            // NIDPLog has no info-with-throwable variant
            NIDPLog.logAppInfo(throwable == null ? message : message + "\n" + stackTrace(throwable));
        } else {
            if (throwable == null) {
                NIDPLog.logAppFine(message);
            } else {
                NIDPLog.logAppFine(throwable, message);
            }
        }
    }

    private static String stackTrace(Throwable throwable) {
        StringWriter out = new StringWriter();
        throwable.printStackTrace(new PrintWriter(out));
        return out.toString();
    }
}
