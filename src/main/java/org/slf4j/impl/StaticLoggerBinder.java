package org.slf4j.impl;

import com.pointbluetech.nam.login.passkey.logging.NidpLoggerFactory;
import org.slf4j.ILoggerFactory;
import org.slf4j.spi.LoggerFactoryBinder;

/**
 * SLF4J 1.7 binding that routes all logging in this jar to the NAM Identity Server log.
 *
 * The shade plugin relocates this class along with slf4j-api, so the bundled (relocated)
 * LoggerFactory binds here and the IDP's own slf4j / slf4j-simple are never involved.
 */
public final class StaticLoggerBinder implements LoggerFactoryBinder {

    private static final StaticLoggerBinder SINGLETON = new StaticLoggerBinder();

    // Read by LoggerFactory for its version compatibility check; must not be final
    public static String REQUESTED_API_VERSION = "1.7.36";

    private final ILoggerFactory loggerFactory = new NidpLoggerFactory();

    private StaticLoggerBinder() {
    }

    public static StaticLoggerBinder getSingleton() {
        return SINGLETON;
    }

    @Override
    public ILoggerFactory getLoggerFactory() {
        return loggerFactory;
    }

    @Override
    public String getLoggerFactoryClassStr() {
        return NidpLoggerFactory.class.getName();
    }
}
