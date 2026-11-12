package com.pointbluetech.nam.login.passkey;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.nam.common.ldap.jndi.JNDIUserStore;
import com.novell.nam.common.ldap.jndi.JNDIUserStoreReplica;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.authority.ldap.LDAPUserAuthority;
import com.novell.nidp.common.util.net.client.NIDP_SSLSocketFactory;
import com.novell.security.nmas.client.InvalidNMASCallbackException;
import com.novell.security.nmas.client.MAF;
import com.novell.security.nmas.client.NMASCallback;
import com.novell.security.nmas.client.NMASCallbackHandler;
import com.novell.security.nmas.client.NMASCompletionCallback;
import com.novell.security.nmas.lcm.LCM;
import com.novell.security.nmas.lcm.registry.LCMRegistry;
import com.novell.security.nmas.lcm.registry.LCMRegistryException;
import com.novell.security.nmas.nidp.NidpAdapterSSLSocketFactory;
import com.novell.security.nmas.transport.MAFTransportException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * An NMAS challenge-response login against eDirectory, as NAM's own NMAS method runs one: a SASL
 * NMAS_LOGIN bind through NAM's JLDAP (ldap.jar) and NMAS client (nmasclient.jar), over NAM's
 * trusted TLS socket factory, to a replica of the user's own user store. The challenge-response
 * method runs here on the IDP, in {@link Module}, instead of in a browser plugin, so no extra jar
 * is needed. Only this class refers to NMAS or JLDAP: if those jars are missing, the error stays here.
 */
final class NmasLogin {

    /** How long one LDAP operation may wait for eDirectory. */
    private static final int OPERATION_TIMEOUT_MS = 30_000;

    private NmasLogin() {
    }

    /** One replica to try. */
    static final class Target {
        final String host;
        final int port;
        final boolean tls;

        Target(String host, int port, boolean tls) {
            this.host = host;
            this.port = port;
            this.tls = tls;
        }

        @Override
        public String toString() {
            return (tls ? "ldaps://" : "ldap://") + host + ":" + port;
        }
    }

    /** The replicas of the user's own user store, if it's an eDirectory one, in NAM's order. */
    static List<Target> targets(NIDPPrincipal principal) {
        List<Target> targets = new ArrayList<>();
        UserAuthority authority = principal.getAuthority();
        if (!(authority instanceof LDAPUserAuthority)) {
            return targets;
        }
        JNDIUserStore store = ((LDAPUserAuthority) authority).getStore();
        if (store == null || store.getDirType() != JNDIUserStore.DIRTYPE_EDIR) {
            return targets;
        }
        for (JNDIUserStoreReplica replica : store.getUserStoreReplicas()) {
            String host = replica.getHost();
            if (host == null || host.trim().isEmpty()) {
                continue;
            }
            host = host.trim();
            // NAM's own NMAS method strips a scheme some configurations include
            for (String scheme : new String[] {"ldaps://", "ldap://"}) {
                if (host.toLowerCase(Locale.ROOT).startsWith(scheme)) {
                    host = host.substring(scheme.length());
                }
            }
            targets.add(new Target(host, replica.getPort(), replica.getDoSSL()));
        }
        return targets;
    }

    /**
     * The login for a check: binds as the user with the login sequence, trying each replica until
     * one connects. The connection is closed as soon as the login ends, right or wrong.
     */
    static NmasCheck.Login login(String userDn, List<Target> targets, String sequence) {
        return check -> {
            Handler handler = new Handler(check, userDn, sequence);
            LDAPException lastConnectFailure = null;
            for (Target target : targets) {
                LDAPConnection connection = target.tls
                        ? new LDAPConnection(new NidpAdapterSSLSocketFactory(NIDP_SSLSocketFactory.getInstance()))
                        : new LDAPConnection();
                try {
                    try {
                        connection.connect(target.host, target.port);
                    } catch (LDAPException e) {
                        lastConnectFailure = e;
                        continue;
                    }
                    return bind(connection, handler, userDn, sequence);
                } finally {
                    disconnect(connection);
                }
            }
            throw lastConnectFailure != null ? lastConnectFailure : new IOException("No replica to connect to");
        };
    }

    private static int bind(LDAPConnection connection, Handler handler, String userDn, String sequence) {
        Map<String, Object> properties = new HashMap<>();
        properties.put("com.novell.security.sasl.client.pkgs", "com.novell.sasl.client");
        properties.put("javax.security.sasl.client.pkgs", "com.novell.sasl.client");
        properties.put("LoginSequence", sequence);
        LDAPConstraints constraints = new LDAPConstraints();
        constraints.setTimeLimit(OPERATION_TIMEOUT_MS);
        try {
            connection.bind(userDn, "dn:" + userDn, new String[] {"NMAS_LOGIN"}, properties, handler, constraints);
        } catch (LDAPException e) {
            int code = handler.completion();
            return code != 0 ? code : NmasCheck.CANCELLED;
        }
        if (connection.isBound()) {
            return 0;
        }
        int code = handler.completion();
        return code != 0 ? code : NmasCheck.CANCELLED;
    }

    private static void disconnect(LDAPConnection connection) {
        try {
            if (connection.isConnected()) {
                connection.disconnect();
            }
        } catch (LDAPException e) {
            // Nothing to keep from a connection we're done with
        }
    }

    /** Answers NMAS's own questions, and records how the login ended. */
    static final class Handler extends NMASCallbackHandler {
        final NmasCheck check;
        private volatile Integer completion;

        Handler(NmasCheck check, String userDn, String sequence) {
            super(new Registry());
            this.check = check;
            setUserDN(userDn);
            setLoginSequence(sequence);
            // The method runs here, not in a browser plugin
            setNativePluginFlag(false);
        }

        @Override
        public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof NMASCallback) {
                    NMASCallback nmas = (NMASCallback) callback;
                    if (nmas.getRequestType() == NMASCallback.COMPLETION_STATUS) {
                        completion = nmas.getCompletionStatus();
                    }
                    try {
                        handleNMASCallback(nmas);
                    } catch (InvalidNMASCallbackException e) {
                        throw new UnsupportedCallbackException(callback);
                    }
                } else if (callback instanceof NMASCompletionCallback) {
                    completion = ((NMASCompletionCallback) callback).getNmasStatus();
                    setNmasRetCode(completion);
                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        }

        /** NMAS's status when the login ended, or 0 if it hasn't said. Never waits. */
        int completion() {
            Integer code = completion;
            return code == null ? 0 : code;
        }
    }

    /** Offers NMAS only our challenge-response method. */
    static final class Registry implements LCMRegistry {
        @Override
        public void update() {
        }

        @Override
        public int[] getCanDo() {
            return new int[] {NmasChallengeProtocol.METHOD_ID};
        }

        @Override
        public LCM getMethodInstance(int methodId) throws LCMRegistryException {
            if (methodId != NmasChallengeProtocol.METHOD_ID) {
                throw new LCMRegistryException();
            }
            return new Module();
        }
    }

    /** NMAS method 31, Challenge Response, run on the IDP with the answers from the web page. */
    static final class Module implements LCM {
        @Override
        public Integer getMethodID() {
            return NmasChallengeProtocol.METHOD_ID;
        }

        @Override
        public String getMethodName() {
            return "Challenge Response";
        }

        @Override
        public int doMethod(MAF maf, CallbackHandler callbackHandler) {
            if (!(callbackHandler instanceof Handler)) {
                return NmasCheck.CANCELLED;
            }
            NmasCheck check = ((Handler) callbackHandler).check;
            NmasChallengeProtocol.Wire wire = new NmasChallengeProtocol.Wire() {
                @Override
                public int write(byte[] message) throws Exception {
                    return maf.write(message);
                }

                @Override
                public byte[] read() throws Exception {
                    return maf.read(0);
                }
            };
            try {
                return NmasChallengeProtocol.exchange(wire, check::ask);
            } catch (MAFTransportException e) {
                return e.getErrorCode();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return NmasCheck.CANCELLED;
            } catch (Exception e) {
                return NmasCheck.TRANSPORT_FAILED;
            }
        }
    }
}
