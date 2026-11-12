package com.pointbluetech.nam.login.passkey.logging;

import java.util.function.Supplier;
import java.util.logging.Level;
import org.slf4j.helpers.FormattingTuple;
import org.slf4j.helpers.MarkerIgnoringBase;
import org.slf4j.helpers.MessageFormatter;

/**
 * SLF4J logger that forwards to a {@link NidpLogSink}.
 *
 * Level mapping: trace/debug -> FINE, info -> INFO, warn -> WARNING, error -> SEVERE.
 * Every message is prefixed with {@code [Passkey:<simple logger name>]} so library output can be
 * found in the IDP log.
 */
public final class NidpLoggerAdapter extends MarkerIgnoringBase {

    private static final long serialVersionUID = 1L;

    private final transient Supplier<NidpLogSink> sink;
    private final String prefix;

    NidpLoggerAdapter(String loggerName, Supplier<NidpLogSink> sink) {
        this.name = loggerName;
        this.sink = sink;
        this.prefix = "[Passkey:" + simpleName(loggerName) + "] ";
    }

    static String simpleName(String loggerName) {
        if (loggerName == null || loggerName.isEmpty()) {
            return "root";
        }
        int dot = loggerName.lastIndexOf('.');
        return dot < 0 ? loggerName : loggerName.substring(dot + 1);
    }

    private boolean enabled(Level level) {
        return sink.get().isEnabled(level);
    }

    private void log(Level level, String message, Throwable throwable) {
        NidpLogSink target = sink.get();
        if (target.isEnabled(level)) {
            target.log(level, prefix + message, throwable);
        }
    }

    private void format(Level level, String format, Object... args) {
        NidpLogSink target = sink.get();
        if (target.isEnabled(level)) {
            // arrayFormat treats a trailing Throwable argument as the exception
            FormattingTuple tuple = MessageFormatter.arrayFormat(format, args);
            target.log(level, prefix + tuple.getMessage(), tuple.getThrowable());
        }
    }

    // trace -> FINE

    @Override public boolean isTraceEnabled() { return enabled(Level.FINE); }
    @Override public void trace(String msg) { log(Level.FINE, msg, null); }
    @Override public void trace(String format, Object arg) { format(Level.FINE, format, arg); }
    @Override public void trace(String format, Object arg1, Object arg2) { format(Level.FINE, format, arg1, arg2); }
    @Override public void trace(String format, Object... arguments) { format(Level.FINE, format, arguments); }
    @Override public void trace(String msg, Throwable t) { log(Level.FINE, msg, t); }

    // debug -> FINE

    @Override public boolean isDebugEnabled() { return enabled(Level.FINE); }
    @Override public void debug(String msg) { log(Level.FINE, msg, null); }
    @Override public void debug(String format, Object arg) { format(Level.FINE, format, arg); }
    @Override public void debug(String format, Object arg1, Object arg2) { format(Level.FINE, format, arg1, arg2); }
    @Override public void debug(String format, Object... arguments) { format(Level.FINE, format, arguments); }
    @Override public void debug(String msg, Throwable t) { log(Level.FINE, msg, t); }

    // info -> INFO

    @Override public boolean isInfoEnabled() { return enabled(Level.INFO); }
    @Override public void info(String msg) { log(Level.INFO, msg, null); }
    @Override public void info(String format, Object arg) { format(Level.INFO, format, arg); }
    @Override public void info(String format, Object arg1, Object arg2) { format(Level.INFO, format, arg1, arg2); }
    @Override public void info(String format, Object... arguments) { format(Level.INFO, format, arguments); }
    @Override public void info(String msg, Throwable t) { log(Level.INFO, msg, t); }

    // warn -> WARNING

    @Override public boolean isWarnEnabled() { return enabled(Level.WARNING); }
    @Override public void warn(String msg) { log(Level.WARNING, msg, null); }
    @Override public void warn(String format, Object arg) { format(Level.WARNING, format, arg); }
    @Override public void warn(String format, Object arg1, Object arg2) { format(Level.WARNING, format, arg1, arg2); }
    @Override public void warn(String format, Object... arguments) { format(Level.WARNING, format, arguments); }
    @Override public void warn(String msg, Throwable t) { log(Level.WARNING, msg, t); }

    // error -> SEVERE

    @Override public boolean isErrorEnabled() { return enabled(Level.SEVERE); }
    @Override public void error(String msg) { log(Level.SEVERE, msg, null); }
    @Override public void error(String format, Object arg) { format(Level.SEVERE, format, arg); }
    @Override public void error(String format, Object arg1, Object arg2) { format(Level.SEVERE, format, arg1, arg2); }
    @Override public void error(String format, Object... arguments) { format(Level.SEVERE, format, arguments); }
    @Override public void error(String msg, Throwable t) { log(Level.SEVERE, msg, t); }
}
