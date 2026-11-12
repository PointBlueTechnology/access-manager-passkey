package com.pointbluetech.nam.login.passkey;

import com.novell.nam.common.ldap.jndi.JNDIException;
import com.novell.nam.common.ldap.jndi.JNDIUserStore;
import com.novell.nam.common.ldap.jndi.JNDIUserStoreSearchContext;
import com.novell.nidp.NIDPConstants;
import com.novell.nidp.NIDPContext;
import com.novell.nidp.NIDPException;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.authentication.AuthenticationContract;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.authentication.local.PageToShow;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.authority.ldap.LDAPPrincipal;
import com.novell.nidp.common.authority.ldap.LDAPUserAuthority;
import com.novell.nidp.logging.NIDPLog;
import com.pointbluetech.nam.login.passkey.logging.LogText;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * NAM authentication class for WebAuthn passkeys.
 *
 * Configured in Administration Console as an "Other" class with Java class
 * {@code com.pointbluetech.nam.login.passkey.PasskeyAuthClass}; behavior per method is chosen by
 * the {@code MODE} property (see docs/DESIGN.md).
 *
 * NAM creates instances freely during a login, so this class keeps no per-login fields: ceremony
 * state lives in the session ({@link CeremonyState}) and the rules in {@link PasskeyService}.
 * All modes are implemented: MFA with inline enrollment, MANAGE, LOGIN where the passkey is the only
 * factor, RECOVERY for users who lost every passkey, HELPDESK for issuing recovery tokens, and
 * UPGRADE, where the browser's password manager may create a passkey by itself after a password.
 */
public class PasskeyAuthClass extends LocalAuthenticationClass {

    private static final String LOG_PREFIX = "[Passkey] ";

    private static final String ACTION_ASSERT = "assert";
    private static final String ACTION_REGISTER = "register";
    private static final String ACTION_ADD = "add";
    private static final String ACTION_DONE = "done";
    private static final String ACTION_RENAME = "rename";
    private static final String ACTION_DELETE = "delete";
    private static final String ACTION_IDENTIFY = "identify";
    private static final String ACTION_CODES = "codes";
    private static final String ACTION_RECOVER = "recover";
    private static final String ACTION_ISSUE = "issue";
    private static final String ACTION_GATE = "gate";
    private static final String ACTION_GATE_SEND = "gate_send";
    private static final String ACTION_SKIP = "skip";

    private static final String PARAM_ACTION = "pk_action";
    private static final String PARAM_RESPONSE = "pk_response";
    private static final String PARAM_NAME = "pk_name";
    private static final String PARAM_CREDENTIAL = "pk_cred_id";
    private static final String PARAM_TOKEN = "pk_token";
    private static final String PARAM_USER_ID = "pk_userid";
    private static final String PARAM_CODE = "pk_code";
    private static final String PARAM_TARGET = "pk_target";
    private static final String PARAM_REASON = "pk_reason";
    private static final int HELPDESK_CHECKS = 3;
    private static final long GATE_CODE_TTL_MS = 10 * 60 * 1000L;
    private static final int GATE_CODE_MAX_SENDS = 5;
    /** How long a request waits for eDirectory during an NMAS security-questions login. */
    private static final long NMAS_WAIT_MS = 20_000;
    /** The shortest reply to NMAS security answers, right or wrong. */
    private static final long NMAS_MIN_ANSWER_MS = 1_000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final DateTimeFormatter EXPIRY =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    private static final String STATE_REGISTER = "register";
    private static final String STATE_SAVED = "saved";
    private static final String STATE_IDENTIFIED = "identified";
    private static final String STATE_START = "start";

    /** The login policy check passed, or passed but couldn't record the login. */
    private static final int POLICY_OK = 0;
    private static final int POLICY_OK_NOT_RECORDED = 2;

    /** So a server logs each configuration once, not on every instance NAM creates. */
    private static final Set<String> LOGGED_CONFIGS = ConcurrentHashMap.newKeySet();

    /** One queue and thread for the whole server, since NAM creates instances of this class all the time. */
    private static final Notifier NOTIFIER = new Notifier(Notifier.newMailThread(), Notifier::namSender,
            new Notifier.Log() {
                @Override
                public void fine(String message) {
                    logFine(message);
                }

                @Override
                public void info(String message) {
                    logInfo(message);
                }

                @Override
                public void warning(String message) {
                    logWarning(message);
                }
            });

    private final PasskeyConfig config;

    public PasskeyAuthClass(Properties props, ArrayList<UserAuthority> uStores) throws NIDPException {
        super(props, uStores);
        setCSRFCheckFlag(true);

        try {
            config = PasskeyConfig.from(props);
            // Touches the shaded Yubico classes so a broken deployment fails here, not mid-login
            RelyingPartyIdentity rp = RelyingPartyFactory.identity(config);
            if (LOGGED_CONFIGS.add(config.describe())) {
                logInfo("PasskeyAuthClass " + version() + " initialized: " + config.describe() + ", rpName=" + rp.getName());
                if (config.mode() == PasskeyConfig.Mode.LOGIN && config.allowIdentifierFirst()
                        && !config.recoveryPepper().isPresent()) {
                    logWarning("Set RECOVERY_PEPPER, the same on every Identity Server node: without it, the decoys"
                            + " that hide which IDs have passkeys differ between nodes and after a restart");
                }
            }
        } catch (IllegalArgumentException e) {
            if (NIDPLog.isLoggableAppWarning()) {
                NIDPLog.logAppWarning(LOG_PREFIX + LogText.clean("PasskeyAuthClass INIT FAILED: " + e.getMessage()));
            }
            throw new NIDPException("PasskeyAuthClass INIT FAILED: " + e.getMessage());
        }
    }

    @Override
    protected int doAuthenticate() {
        if (config.mode() == PasskeyConfig.Mode.LOGIN) {
            return doLogin();
        }
        NIDPPrincipal principal = principalFromPreviousMethod();
        if (principal == null) {
            logFine("no principal from a previous method");
            return showError("error.noUser");
        }

        try {
            UserAccount account = accountFor(principal);
            CeremonyState state = new CeremonyState(sessionProperties(), scope(), account.guid(),
                    config.challengeTtlSec(), Clock.systemUTC());
            if (isFirstCallAfterPrevMethod()) {
                state.clear();
            }
            PasskeyStore store = new PasskeyStore(new NamUserAttributes(principal, m_Session),
                    config.passkeyAttribute(), config.auxClass());
            PasskeyService service = new PasskeyService(config, account, store, state, Clock.systemUTC());
            switch (config.mode()) {
                case MANAGE:
                    return handleManage(service, state, principal);
                case RECOVERY:
                    return handleRecovery(service, state, principal);
                case HELPDESK:
                    return handleHelpdesk(service, state, principal);
                case UPGRADE:
                    return handleUpgrade(service, state, principal);
                default:
                    return handle(service, state, principal);
            }
        } catch (IllegalArgumentException e) {
            logWarning("Cannot use passkeys for " + principal.getUserIdentifier() + ": " + e.getMessage());
            return config.mode() == PasskeyConfig.Mode.UPGRADE ? finishWithoutUpgrade(principal) : showError("error.account");
        } catch (PasskeyStoreException e) {
            // Never carry on as if the user had no passkeys
            logWarning(e.getMessage());
            return config.mode() == PasskeyConfig.Mode.UPGRADE ? finishWithoutUpgrade(principal) : showError("error.store");
        }
    }

    /**
     * UPGRADE mode, after a password: for a user with no passkey, the page asks the browser to create
     * one by itself (WebAuthn conditional create). Browsers do that only when their password manager
     * just filled in this user's password, and the user sees at most a notice that it was saved.
     * It never stands in the way of signing in: no passkey, a browser that can't, a refusal or an
     * error all simply finish the method, so the password alone still signs the user in.
     */
    private int handleUpgrade(PasskeyService service, CeremonyState state, NIDPPrincipal principal) {
        String action = m_Request.getParameter(PARAM_ACTION);
        String user = principal.getUserIdentifier();
        logFine("doAuthenticate upgrade action=" + action + ", firstCall=" + isFirstCallAfterPrevMethod());

        if (ACTION_REGISTER.equals(action)) {
            try {
                PasskeyRecord added = service.finishRegistration(m_Request.getParameter(PARAM_RESPONSE), null);
                logInfo("The browser created passkey '" + added.name() + "' for " + user + " after the password");
                notifyUser(Notification.PASSKEY_ADDED, principal, added.name());
            } catch (CeremonyFailedException e) {
                logWarning("Automatic passkey upgrade failed for " + user + ": " + e.getMessage());
            }
            return signIn(state, principal);
        }
        if (action != null) {
            logFine("No automatic passkey for " + user + ": " + upgradeSkipReason());
            return signIn(state, principal);
        }
        if (!service.mayRegister(service.passkeys())) {
            logFine("No automatic passkey for " + user + ": already has one");
            return signIn(state, principal);
        }
        if (isFramePageNeeded()) {
            return showFramePage(state, null);
        }
        try {
            PageToShow page = page(config.upgradeJsp(), null);
            page.addAttribute("pk_options", (Object) PasskeyMessages.jsonForScriptTag(service.startRegistration()));
            return SHOW_JSP;
        } catch (CeremonyFailedException e) {
            logFine("No automatic passkey for " + user + ": " + e.getMessage());
            return signIn(state, principal);
        }
    }

    /** What the page reported, kept to a short word: it's from the browser, so it may be anything. */
    private String upgradeSkipReason() {
        String reason = m_Request.getParameter(PARAM_REASON);
        return reason != null && reason.matches("[A-Za-z]{1,40}") ? reason : "unknown";
    }

    /** The password has already signed the user in; a passkey problem mustn't undo that. */
    private int finishWithoutUpgrade(NIDPPrincipal principal) {
        setPrincipal(principal);
        return AUTHENTICATED;
    }

    /** LOGIN mode: nobody has been identified yet, so the state belongs to no particular user. */
    private int doLogin() {
        if (!isDefinesUser()) {
            logWarning("A LOGIN mode method must have Identifies User turned on");
            return showError("error.mode");
        }
        try {
            CeremonyState state = new CeremonyState(sessionProperties(), scope(), "login",
                    config.challengeTtlSec(), Clock.systemUTC());
            if (isFirstCallAfterPrevMethod()) {
                state.clear();
            }
            PasskeyLogin login = new PasskeyLogin(config, new NamUserDirectory(), state, Clock.systemUTC());
            try {
                return handleLogin(login, state);
            } catch (PasskeyStoreException e) {
                // The page itself needs no directory, so the user can simply try again from it
                logWarning(e.getMessage());
                return showLogin(login, state, "error.tryAgain");
            }
        } catch (PasskeyStoreException e) {
            logWarning(e.getMessage());
            return showError("error.store");
        }
    }

    private int handleLogin(PasskeyLogin login, CeremonyState state) {
        String action = m_Request.getParameter(PARAM_ACTION);
        logFine("doAuthenticate login action=" + action + ", firstCall=" + isFirstCallAfterPrevMethod());

        if (ACTION_ASSERT.equals(action)) {
            try {
                NIDPPrincipal principal = (NIDPPrincipal) login.finish(m_Request.getParameter(PARAM_RESPONSE)).principal();
                if (!mayLogIn(principal)) {
                    return showLogin(login, state, "error.loginFailed");
                }
                setPrincipal(principal);
                setUserId(principal.getUserIdentifier());
                addLDAPCredentials();
                state.clear();
                return AUTHENTICATED;
            } catch (CeremonyFailedException e) {
                logWarning("Passkey sign-in failed: " + e.getMessage());
                return showLogin(login, state, e.messageKey());
            }
        }
        if (ACTION_IDENTIFY.equals(action) && config.allowIdentifierFirst() && !isFramePageNeeded()) {
            String id = m_Request.getParameter(PARAM_USER_ID);
            PageToShow page = page(config.loginJsp(), null);
            page.addAttribute("pk_options", (Object) PasskeyMessages.jsonForScriptTag(login.startForId(id)));
            page.addAttribute("pk_state", STATE_IDENTIFIED);
            page.addAttribute("pk_userid", id == null ? "" : id.trim());
            return SHOW_JSP;
        }
        return showLogin(login, state, null);
    }

    /**
     * No password was checked, so the directory hasn't had a chance to refuse this account. Anything
     * but a clear pass refuses it: a check that couldn't run can't vouch for a disabled account.
     */
    private boolean mayLogIn(NIDPPrincipal principal) {
        UserAuthority authority = principal.getAuthority();
        if (authority == null || !authority.isActiveDirectory()) {
            // NAM's check below is enough on AD, where it reads userAccountControl itself
            try {
                NamUserAttributes attributes = new NamUserAttributes(principal, m_Session);
                if (NIDPLog.isLoggableAppFine()) {
                    // Not secrets; shows whether the proxy account can read them at all
                    StringBuilder seen = new StringBuilder();
                    for (String attribute : AccountRestrictions.EDIRECTORY_ATTRIBUTES) {
                        seen.append(' ').append(attribute).append('=').append(attributes.read(attribute));
                    }
                    logFine("Account restrictions read for " + principal.getUserIdentifier() + ":" + seen);
                }
                Optional<String> refusal = AccountRestrictions.refusal(attributes, Instant.now());
                if (refusal.isPresent()) {
                    logWarning("Login policy refused " + principal.getUserIdentifier() + " (" + refusal.get() + ")");
                    return false;
                }
            } catch (PasskeyStoreException e) {
                logWarning("Login policy check failed for " + principal.getUserIdentifier() + ": " + e.getMessage());
                return false;
            }
        }
        try {
            int result = principal.getAuthority().doLoginPolicyCheck(principal);
            if (result != POLICY_OK && result != POLICY_OK_NOT_RECORDED) {
                logWarning("Login policy refused " + principal.getUserIdentifier() + " (result " + result + ")");
                return false;
            }
            return true;
        } catch (NIDPException e) {
            logWarning("Login policy check failed for " + principal.getUserIdentifier() + ": " + e.getMessage());
            return false;
        }
    }

    private int showLogin(PasskeyLogin login, CeremonyState state, String messageKey) {
        if (isFramePageNeeded()) {
            return showFramePage(state, messageKey);
        }
        String message = messageKey != null ? messageKey : state.takePendingMessage().orElse(null);
        PageToShow page = page(config.loginJsp(), message);
        page.addAttribute("pk_state", STATE_START);
        page.addAttribute("pk_allow_id", Boolean.valueOf(config.allowIdentifierFirst()));
        page.addAttribute("pk_allow_usernameless", Boolean.valueOf(config.allowUsernameless()));
        if (config.allowUsernameless()) {
            page.addAttribute("pk_options", (Object) PasskeyMessages.jsonForScriptTag(login.startUsernameless()));
        }
        return SHOW_JSP;
    }

    /** {@link UserDirectory} over the method's user stores. */
    private final class NamUserDirectory implements UserDirectory {

        @Override
        public Optional<User> byGuid(String guid) {
            for (UserAuthority store : m_UserStores) {
                NIDPPrincipal principal = store.getPrincipalByGUID(guid, new ArrayList<>());
                if (principal != null) {
                    return user(principal);
                }
            }
            checkDirectoryReachable();
            return Optional.empty();
        }

        @Override
        public Optional<User> byId(String id) {
            NIDPPrincipal[] found = findPrincipals(escapeName(id));
            if (found != null && found.length > 0) {
                return found.length == 1 ? user(found[0]) : Optional.empty();
            }
            checkDirectoryReachable();
            return Optional.empty();
        }

        /**
         * NAM's searches return "no such user" when the search itself failed, for example on a pooled
         * connection that has died, and that connection can come straight back on a retry. Reading
         * an entry directly does report the failure, so check before believing a miss.
         */
        private void checkDirectoryReachable() {
            for (UserAuthority store : m_UserStores) {
                if (store instanceof LDAPUserAuthority) {
                    JNDIUserStore directory = ((LDAPUserAuthority) store).getStore();
                    JNDIUserStoreSearchContext context = directory.getSearchContext(0);
                    if (context == null) {
                        continue;
                    }
                    try {
                        directory.getObject(context.getContext(), context.getContext(), new String[] {"objectClass"});
                    } catch (JNDIException e) {
                        throw new PasskeyStoreException("User lookup failed, directory read failed: " + e, e);
                    }
                }
            }
        }

        private Optional<User> user(NIDPPrincipal principal) {
            try {
                return Optional.of(new User(accountFor(principal),
                        new PasskeyStore(new NamUserAttributes(principal, m_Session),
                                config.passkeyAttribute(), config.auxClass()),
                        principal));
            } catch (IllegalArgumentException e) {
                logWarning("Cannot use passkeys for " + principal.getUserIdentifier() + ": " + e.getMessage());
                return Optional.empty();
            }
        }
    }

    private int handle(PasskeyService service, CeremonyState state, NIDPPrincipal principal) {
        String action = m_Request.getParameter(PARAM_ACTION);
        logFine("doAuthenticate action=" + action + ", firstCall=" + isFirstCallAfterPrevMethod());
        Optional<Integer> gated = enrollGate(service, state, principal, action);
        if (gated.isPresent()) {
            return gated.get();
        }

        if (ACTION_ASSERT.equals(action)) {
            try {
                service.finishAssertion(m_Request.getParameter(PARAM_RESPONSE));
                return signIn(state, principal);
            } catch (CeremonyFailedException e) {
                logWarning("Passkey sign-in failed for " + principal.getUserIdentifier() + ": " + e.getMessage());
                return showCurrentPage(service, state, e.messageKey());
            }
        }
        if (ACTION_REGISTER.equals(action)) {
            try {
                PasskeyRecord saved = service.finishRegistration(m_Request.getParameter(PARAM_RESPONSE),
                        m_Request.getParameter(PARAM_NAME));
                notifyUser(Notification.PASSKEY_ADDED, principal, saved.name());
                Optional<List<String>> codes = firstRecoveryCodes(principal);
                return codes.isPresent() ? showCodes(codes.get()) : showSaved(state, saved.name());
            } catch (CeremonyFailedException e) {
                logWarning("Passkey registration failed for " + principal.getUserIdentifier() + ": " + e.getMessage());
                return showCurrentPage(service, state, e.messageKey());
            }
        }
        if (ACTION_ADD.equals(action) && state.enrolling()) {
            return showRegister(service, state, null);
        }
        if (ACTION_DONE.equals(action) && state.enrolling()) {
            return signIn(state, principal);
        }
        return showCurrentPage(service, state, null);
    }

    /**
     * The manage page. Earlier methods in the contract may be only a password, so a user with a
     * passkey must prove one before seeing or changing anything, and again once that proof ages out;
     * an action stopped by that finishes after the user confirms, so they needn't repeat it.
     * "Done" completes the method, so it stays behind the same check.
     */
    private int handleManage(PasskeyService service, CeremonyState state, NIDPPrincipal principal) {
        String action = m_Request.getParameter(PARAM_ACTION);
        logFine("doAuthenticate manage action=" + action + ", firstCall=" + isFirstCallAfterPrevMethod());
        String user = principal.getUserIdentifier();
        Optional<Integer> gated = enrollGate(service, state, principal, action);
        if (gated.isPresent()) {
            return gated.get();
        }

        if (ACTION_ASSERT.equals(action)) {
            try {
                service.finishAssertion(m_Request.getParameter(PARAM_RESPONSE));
            } catch (CeremonyFailedException e) {
                logWarning("Passkey confirmation failed for " + user + ": " + e.getMessage());
                return showManage(service, state, e.messageKey());
            }
            Optional<String[]> pending = state.takePendingAction();
            if (pending.isPresent()) {
                String[] waiting = pending.get();
                return performManageAction(service, state, principal, waiting[0], waiting[1], waiting[2]);
            }
            return showManage(service, state, null);
        }
        if (ACTION_REGISTER.equals(action)) {
            if (!service.manageUnlocked(service.passkeys())) {
                // The challenge it answers can't be kept while another passkey is confirmed
                return showManage(service, state, "error.confirmAddAgain");
            }
            try {
                PasskeyRecord added = service.finishRegistration(m_Request.getParameter(PARAM_RESPONSE),
                        m_Request.getParameter(PARAM_NAME));
                notifyUser(Notification.PASSKEY_ADDED, principal, added.name());
                Optional<List<String>> codes = firstRecoveryCodes(principal);
                return codes.isPresent() ? showCodes(codes.get()) : showManage(service, state, "manage.added");
            } catch (CeremonyFailedException e) {
                logWarning("Passkey registration failed for " + user + ": " + e.getMessage());
                return showManage(service, state, e.messageKey());
            }
        }
        if (!isManageAction(action)) {
            return showManage(service, state, null);
        }
        if (!state.checkActionToken(m_Request.getParameter(PARAM_TOKEN))) {
            logWarning("Manage request with a bad token for " + user + ", action=" + action);
            return showManage(service, state, "error.expired");
        }
        String credential = m_Request.getParameter(PARAM_CREDENTIAL);
        String name = m_Request.getParameter(PARAM_NAME);
        if (!service.manageUnlocked(service.passkeys())) {
            // Only the proof has aged out; carry on with this once the user has confirmed
            state.setPendingAction(action, credential, name);
            return showManage(service, state, null);
        }
        return performManageAction(service, state, principal, action, credential, name);
    }

    private static boolean isManageAction(String action) {
        return ACTION_ADD.equals(action) || ACTION_RENAME.equals(action) || ACTION_DELETE.equals(action)
                || ACTION_CODES.equals(action) || ACTION_DONE.equals(action);
    }

    private int performManageAction(PasskeyService service, CeremonyState state, NIDPPrincipal principal,
            String action, String credential, String name) {
        if (!service.manageUnlocked(service.passkeys())) {
            return showManage(service, state, null);
        }
        try {
            if (ACTION_ADD.equals(action)) {
                return showRegister(service, state, null);
            }
            if (ACTION_RENAME.equals(action)) {
                service.rename(credential, name);
                return showManage(service, state, "manage.renamed");
            }
            if (ACTION_DELETE.equals(action)) {
                String removed = service.delete(credential);
                notifyUser(Notification.PASSKEY_REMOVED, principal, removed);
                return showManage(service, state, "manage.removed");
            }
            if (ACTION_CODES.equals(action)) {
                Optional<RecoveryStore> recovery = recoveryFor(principal);
                if (!recovery.isPresent()) {
                    return showManage(service, state, "error.recoveryUnavailable");
                }
                Optional<Instant> blocked = recovery.get().codesBlockedUntil(config.recoveryCooldownSec());
                if (blocked.isPresent()) {
                    logWarning("Refused new recovery codes for " + principal.getUserIdentifier()
                            + ": the account was recovered recently, allowed after " + blocked.get());
                    return showManage(service, state, "error.codesCooldown");
                }
                logInfo("New recovery codes generated for " + principal.getUserIdentifier());
                List<String> codes = recovery.get().generateCodes(config.recoveryCodeCount());
                notifyUser(Notification.CODES_REPLACED, principal, null);
                return showCodes(codes);
            }
        } catch (CeremonyFailedException e) {
            logWarning("Manage action " + action + " refused for " + principal.getUserIdentifier() + ": " + e.getMessage());
            return showManage(service, state, e.messageKey());
        }
        return signIn(state, principal);
    }

    /** The list if this login may see it; otherwise whatever must happen first. */
    private int showManage(PasskeyService service, CeremonyState state, String messageKey) {
        if (isFramePageNeeded()) {
            return showFramePage(state, messageKey);
        }
        String message = messageKey != null ? messageKey : state.takePendingMessage().orElse(null);
        List<PasskeyRecord> passkeys = service.passkeys();
        if (!service.manageUnlocked(passkeys)) {
            if (passkeys.isEmpty()) {
                return showError("error.noPasskey");
            }
            PageToShow page = page(config.mfaJsp(), message);
            page.addAttribute("pk_options", (Object) PasskeyMessages.jsonForScriptTag(service.startAssertion()));
            page.addAttribute("pk_intro", PasskeyMessages.get(m_Request.getLocale(), "manage.confirm"));
            return SHOW_JSP;
        }
        PageToShow page = page(config.manageJsp(), message);
        page.addAttribute("pk_rows", service.views(passkeys));
        page.addAttribute("pk_token", (Object) state.actionToken());
        page.addAttribute("pk_can_add", Boolean.valueOf(passkeys.size() < config.maxPasskeys()));
        page.addAttribute("pk_can_remove", Boolean.valueOf(!config.requireOne() || passkeys.size() > 1));
        page.addAttribute("pk_single_warning",
                Boolean.valueOf(passkeys.size() == 1 && !passkeys.get(0).backupEligible()));
        boolean review = state.recoveryEnrolled();
        Optional<RecoveryStore> recovery = recoveryFor(principalFromPreviousMethod());
        if (recovery.isPresent()) {
            page.addAttribute("pk_codes_left", Integer.toString(recovery.get().codesLeft()));
            Optional<Instant> blocked = recovery.get().codesBlockedUntil(config.recoveryCooldownSec());
            if (blocked.isPresent()) {
                page.addAttribute("pk_codes_after", EXPIRY.format(blocked.get()));
                review = true;
            }
        }
        // After a recovery, someone else may have been first: ask the user to check the list
        if (review) {
            page.addAttribute("pk_review", Boolean.TRUE);
        }
        return SHOW_JSP;
    }

    /**
     * RECOVERY mode: after a code or helpdesk token the user must create a new passkey, and only then
     * reaches the manage page, where they can remove the ones they no longer have. There's no way
     * from here to finish signing in without a new passkey.
     */
    private int handleRecovery(PasskeyService service, CeremonyState state, NIDPPrincipal principal) {
        String action = m_Request.getParameter(PARAM_ACTION);
        String user = principal.getUserIdentifier();
        logFine("doAuthenticate recovery action=" + action + ", firstCall=" + isFirstCallAfterPrevMethod());

        Optional<RecoveryStore> recovery = recoveryFor(principal);
        if (!recovery.isPresent()) {
            return showError("error.recoveryUnavailable");
        }
        if (!state.recovered()) {
            if (state.failures() >= config.maxFailed()) {
                return showError("error.tooManyAttempts");
            }
            if (!ACTION_RECOVER.equals(action)) {
                return showRecovery(state, null);
            }
            RecoveryStore.Match match = recovery.get().consume(m_Request.getParameter(PARAM_CODE));
            if (match == RecoveryStore.Match.NONE) {
                int failures = state.addFailure();
                logWarning("Wrong recovery code for " + user + " (" + failures + " of " + config.maxFailed() + ")");
                return failures >= config.maxFailed()
                        ? showError("error.tooManyAttempts")
                        : showRecovery(state, "error.recoveryCode");
            }
            // Fails closed: without the time recorded, a cool-down couldn't hold back new codes
            recovery.get().markRecovered();
            logInfo("Account recovery started for " + user + " with a "
                    + (match == RecoveryStore.Match.CODE ? "recovery code" : "helpdesk token"));
            notifyUser(match == RecoveryStore.Match.CODE ? Notification.RECOVERED_WITH_CODE
                    : Notification.RECOVERED_WITH_TOKEN, principal, null);
            state.setRecovered();
            return showRegister(service, state, null);
        }
        if (state.recoveryEnrolled()) {
            return handleManage(service, state, principal);
        }
        if (ACTION_REGISTER.equals(action)) {
            try {
                PasskeyRecord added = service.finishRegistration(m_Request.getParameter(PARAM_RESPONSE),
                        m_Request.getParameter(PARAM_NAME));
                state.setRecoveryEnrolled();
                notifyUser(Notification.PASSKEY_ADDED, principal, added.name());
                logInfo("Account recovery finished for " + user);
                return showManage(service, state, "manage.added");
            } catch (CeremonyFailedException e) {
                logWarning("Passkey registration failed during recovery for " + user + ": " + e.getMessage());
                return showRegister(service, state, e.messageKey());
            }
        }
        return showRegister(service, state, null);
    }

    /**
     * Before a user's first passkey, the checks ENROLL_GATES asks for, one at a time. Empty once
     * there's nothing left to ask, and always for a user who already has a passkey.
     */
    private Optional<Integer> enrollGate(PasskeyService service, CeremonyState state, NIDPPrincipal principal,
            String action) {
        List<PasskeyConfig.EnrollGate> pending = service.pendingGates(service.passkeys());
        if (pending.isEmpty()) {
            return Optional.empty();
        }
        if (state.failures() >= config.maxFailed()) {
            return Optional.of(showError("error.tooManyAttempts"));
        }
        PasskeyConfig.EnrollGate gate = pending.get(0);
        String user = principal.getUserIdentifier();
        if (!ACTION_GATE.equals(action)) {
            return Optional.of(showGate(state, principal, gate, null, ACTION_GATE_SEND.equals(action)));
        }
        String input = m_Request.getParameter(PARAM_CODE);
        boolean passed;
        switch (gate) {
            case EMAIL:
                passed = state.checkGateCode(input, GATE_CODE_TTL_MS);
                break;
            case HELPDESK:
                passed = recoveryFor(principal).map(recovery -> recovery.consumeToken(input)).orElse(false);
                break;
            default:
                if (config.questionStore() == PasskeyConfig.QuestionStore.NMAS) {
                    Optional<NmasCheck> waiting = waitingNmasCheck(state, principal);
                    if (!waiting.isPresent()) {
                        // Not a wrong answer: the login stopped waiting, so ask again
                        logInfo("Security answers for " + user + " came after the NMAS login stopped waiting");
                        return Optional.of(showGate(state, principal, gate, "error.questionsExpired", false));
                    }
                    passed = checkNmasQuestions(state, principal, waiting.get());
                } else {
                    passed = checkQuestions(state, principal);
                }
        }
        if (passed) {
            state.passGate(gate.name());
            logInfo("First-passkey check " + gate + " passed for " + user);
            return Optional.of(pending.size() > 1
                    ? showGate(state, principal, pending.get(1), null, false)
                    : showRegister(service, state, null));
        }
        int failures = state.addFailure();
        String what = gate == PasskeyConfig.EnrollGate.EMAIL ? "setup code"
                : gate == PasskeyConfig.EnrollGate.HELPDESK ? "helpdesk code" : "security answers";
        logWarning("Wrong " + what + " for " + user + " (" + failures + " of " + config.maxFailed() + ")");
        return Optional.of(failures >= config.maxFailed()
                ? showError("error.tooManyAttempts")
                : showGate(state, principal, gate,
                        gate == PasskeyConfig.EnrollGate.QUESTIONS ? "error.questionsWrong" : "error.gateCode", false));
    }

    /** The page for one check; for email, sends a code first if none has been, or if asked to. */
    private int showGate(CeremonyState state, NIDPPrincipal principal, PasskeyConfig.EnrollGate gate,
            String messageKey, boolean resend) {
        if (isFramePageNeeded()) {
            return showFramePage(state, messageKey);
        }
        String message = messageKey != null ? messageKey : state.takePendingMessage().orElse(null);
        if (gate == PasskeyConfig.EnrollGate.HELPDESK) {
            page(config.gateJsp(), message).addAttribute("pk_gate", "helpdesk");
            return SHOW_JSP;
        }
        if (gate == PasskeyConfig.EnrollGate.QUESTIONS) {
            return showQuestions(state, principal, message);
        }
        String user = principal.getUserIdentifier();
        List<String> addresses = Notifier.addresses(
                new NamUserAttributes(principal, m_Session).read(config.notifyMailAttribute()));
        if (addresses.isEmpty()) {
            logWarning("No email address for " + user + " to send a first-passkey setup code to");
            return showError("error.gateNoEmail");
        }
        int sends = state.gateCodeSends();
        if (sends == 0 || resend) {
            if (sends >= GATE_CODE_MAX_SENDS) {
                message = "error.gateResendLimit";
            } else if (!NOTIFIER.ready()) {
                logWarning("Can't email a setup code to " + user + ": NAM's email configuration isn't ready");
                return showError("error.gateEmailUnavailable");
            } else {
                String code = String.format("%06d", RANDOM.nextInt(1_000_000));
                sends = state.issueGateCode(code);
                Locale locale = m_Request.getLocale();
                Map<String, String> values = new HashMap<>();
                values.put("time", EXPIRY.format(Instant.now()));
                values.put("ip", clientAddress(locale));
                values.put("code", code);
                NOTIFIER.submit(Notification.ENROLL_CODE, user, () -> addresses, values, locale);
                logInfo("Emailing a first-passkey setup code to " + user + " (" + sends + " of "
                        + GATE_CODE_MAX_SENDS + ")");
                if (resend) {
                    message = "gate.sent";
                }
            }
        }
        PageToShow page = page(config.gateJsp(), message);
        page.addAttribute("pk_gate", "email");
        page.addAttribute("pk_gate_address", maskAddress(addresses.get(0)));
        page.addAttribute("pk_can_resend", Boolean.valueOf(sends < GATE_CODE_MAX_SENDS));
        return SHOW_JSP;
    }

    /**
     * The user's security questions, as SSPR stores them: every required one, plus as many random
     * ones as their set asks for (at least one if none is required). The same ones are asked until
     * they're answered or the attempts run out.
     */
    private int showQuestions(CeremonyState state, NIDPPrincipal principal, String messageKey) {
        if (config.questionStore() == PasskeyConfig.QuestionStore.NMAS) {
            return showNmasQuestions(state, principal, messageKey);
        }
        Optional<SsprResponses> set = ssprResponses(principal);
        if (!set.isPresent()) {
            return showError("error.questionsNotSet");
        }
        List<Integer> asked = askedQuestions(state, set.get());
        if (asked.isEmpty()) {
            logWarning("No security questions stored for " + principal.getUserIdentifier());
            return showError("error.questionsNotSet");
        }
        List<String> questions = new ArrayList<>();
        for (int index : asked) {
            questions.add(set.get().responses.get(index).question);
        }
        PageToShow page = page(config.gateJsp(), messageKey);
        page.addAttribute("pk_gate", "questions");
        page.addAttribute("pk_questions", (Object) questions);
        return SHOW_JSP;
    }

    private List<Integer> askedQuestions(CeremonyState state, SsprResponses set) {
        Optional<List<Integer>> asked = state.gateQuestions(set.fingerprint);
        if (asked.isPresent()) {
            return asked.get();
        }
        List<Integer> picked = new ArrayList<>(set.required());
        List<Integer> random = new ArrayList<>(set.random());
        Collections.shuffle(random, RANDOM);
        int randoms = Math.min(random.size(), Math.max(set.minRandomRequired, picked.isEmpty() ? 1 : 0));
        picked.addAll(random.subList(0, randoms));
        state.setGateQuestions(set.fingerprint, picked);
        return picked;
    }

    /**
     * Every asked question must be answered right. All are checked, even after a wrong one, so the
     * time taken doesn't show which was wrong. Answers are never logged.
     */
    private boolean checkQuestions(CeremonyState state, NIDPPrincipal principal) {
        Optional<SsprResponses> set = ssprResponses(principal);
        if (!set.isPresent()) {
            return false;
        }
        Optional<List<Integer>> asked = state.gateQuestions(set.get().fingerprint);
        if (!asked.isPresent() || asked.get().isEmpty()) {
            // The stored answers changed since the questions were shown
            return false;
        }
        boolean allRight = true;
        for (int i = 0; i < asked.get().size(); i++) {
            SsprResponses.Response response = set.get().responses.get(asked.get().get(i));
            allRight &= set.get().matches(response, m_Request.getParameter("pk_answer" + i));
        }
        return allRight;
    }

    /**
     * The user's NMAS security questions. eDirectory picks them during an NMAS login, which then
     * waits on its own thread for the answers; a page shown again while it waits shows the same
     * questions. Starting one fails closed, with the reason logged.
     */
    private int showNmasQuestions(CeremonyState state, NIDPPrincipal principal, String messageKey) {
        String user = principal.getUserIdentifier();
        String dn = principal instanceof LDAPPrincipal ? ((LDAPPrincipal) principal).getDN() : null;
        if (dn == null) {
            logWarning("Can't check NMAS security answers for " + user + ": not an LDAP user");
            return showError("error.questionsUnavailable");
        }
        Optional<NmasCheck> check = waitingNmasCheck(state, principal);
        if (!check.isPresent()) {
            state.gateNmas().ifPresent(NmasCheck::forget);
            try {
                List<NmasLogin.Target> targets = NmasLogin.targets(principal);
                if (targets.isEmpty()) {
                    logWarning("Can't check NMAS security answers for " + user
                            + ": the user's store isn't an eDirectory one with a replica");
                    return showError("error.questionsUnavailable");
                }
                check = NmasCheck.start(dn, NmasLogin.login(dn, targets, config.questionsNmasSequence()),
                        config.questionsNmasTimeoutSec() * 1000L);
            } catch (LinkageError e) {
                logWarning("NMAS security answers need NAM's nmasclient.jar and ldap.jar: " + e);
                return showError("error.questionsUnavailable");
            }
            if (!check.isPresent()) {
                logWarning("Too many NMAS logins are waiting for security answers (" + NmasCheck.MAX_CHECKS + ")");
                return showError("error.questionsUnavailable");
            }
            state.setGateNmas(check.get().id);
        }
        NmasCheck waiting = check.get();
        Optional<List<String>> questions;
        try {
            questions = waiting.awaitQuestions(NMAS_WAIT_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            questions = Optional.empty();
        }
        if (!questions.isPresent()) {
            state.setGateNmas(null);
            NmasCheck.forget(waiting.id);
            if (!waiting.done()) {
                logWarning("eDirectory didn't ask " + user + "'s security questions within " + NMAS_WAIT_MS / 1000 + " s");
                return showError("error.questionsUnavailable");
            }
            int code = nmasResult(waiting, 0);
            logWarning("The NMAS login for " + user + " ended before asking security questions (NMAS " + code
                    + waiting.failure().map(f -> ", " + f).orElse("") + ")");
            // A transport failure is ours to fix; anything eDirectory said is most likely no answers set
            return showError(waiting.failure().isPresent() || code == NmasCheck.TRANSPORT_FAILED
                    ? "error.questionsUnavailable" : "error.questionsNotSet");
        }
        PageToShow page = page(config.gateJsp(), messageKey);
        page.addAttribute("pk_gate", "questions");
        page.addAttribute("pk_questions", (Object) questions.get());
        return SHOW_JSP;
    }

    /** This user's NMAS login, if it's still waiting for answers. */
    private Optional<NmasCheck> waitingNmasCheck(CeremonyState state, NIDPPrincipal principal) {
        if (!(principal instanceof LDAPPrincipal)) {
            return Optional.empty();
        }
        String dn = ((LDAPPrincipal) principal).getDN();
        return state.gateNmas()
                .flatMap(id -> NmasCheck.find(id, dn))
                .filter(check -> check.waitingQuestions().isPresent());
    }

    /**
     * Hands the answers to the waiting NMAS login and waits for eDirectory's verdict. eDirectory
     * stops at the first wrong answer, so the reply is held to a minimum time, so it doesn't show
     * which one. Each check is used once. Answers are never logged.
     */
    private boolean checkNmasQuestions(CeremonyState state, NIDPPrincipal principal, NmasCheck check) {
        long started = System.nanoTime();
        List<String> questions = check.waitingQuestions().orElse(Collections.emptyList());
        List<String> answers = new ArrayList<>();
        for (int i = 0; i < questions.size(); i++) {
            String answer = m_Request.getParameter("pk_answer" + i);
            answers.add(answer == null ? "" : answer);
        }
        state.setGateNmas(null);
        int code = check.answer(answers) ? nmasResult(check, NMAS_WAIT_MS) : NmasCheck.CANCELLED;
        NmasCheck.forget(check.id);
        long left = NMAS_MIN_ANSWER_MS - (System.nanoTime() - started) / 1_000_000;
        if (left > 0) {
            try {
                Thread.sleep(left);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (code != 0) {
            logInfo("eDirectory refused the security answers for " + principal.getUserIdentifier() + " (NMAS " + code
                    + check.failure().map(f -> ", " + f).orElse("") + ")");
        }
        return code == 0;
    }

    private static int nmasResult(NmasCheck check, long timeoutMs) {
        try {
            return check.awaitResult(timeoutMs).orElse(NmasCheck.CANCELLED);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return NmasCheck.CANCELLED;
        }
    }

    /** Fails closed: unreadable stored answers can't be passed, and the reason is logged. */
    private Optional<SsprResponses> ssprResponses(NIDPPrincipal principal) {
        List<String> values = new NamUserAttributes(principal, m_Session).read(config.questionsSsprAttribute());
        try {
            return SsprResponses.from(values);
        } catch (IllegalArgumentException e) {
            logWarning("Can't read the SSPR security answers for " + principal.getUserIdentifier() + " from "
                    + config.questionsSsprAttribute() + ": " + e.getMessage());
            return Optional.empty();
        }
    }

    /** Enough of the address for the user to know which one; j•••@example.com. */
    static String maskAddress(String address) {
        int at = address.indexOf('@');
        return at <= 0 ? "\u2022\u2022\u2022" : address.charAt(0) + "\u2022\u2022\u2022" + address.substring(at);
    }

    private int showRecovery(CeremonyState state, String messageKey) {
        if (isFramePageNeeded()) {
            return showFramePage(state, messageKey);
        }
        String message = messageKey != null ? messageKey : state.takePendingMessage().orElse(null);
        page(config.recoveryJsp(), message);
        return SHOW_JSP;
    }

    /**
     * HELPDESK mode. Agents are named in HELPDESK_ALLOWED_DNS or are in the group, whose membership is
     * read fresh on every request; anything but a clear yes refuses. Every agent must also prove their
     * own passkey: a helpdesk account's password alone must not be able to hand out ways into other
     * accounts.
     */
    private int handleHelpdesk(PasskeyService service, CeremonyState state, NIDPPrincipal principal) {
        String action = m_Request.getParameter(PARAM_ACTION);
        String agent = principal.getUserIdentifier();
        logFine("doAuthenticate helpdesk action=" + action + ", firstCall=" + isFirstCallAfterPrevMethod());

        if (!config.isHelpdeskAllowedDn(agent) && !isHelpdeskMember(principal)) {
            logWarning("Refused helpdesk access for " + agent + ": not in " + config.helpdeskGroupDn());
            return showError("error.notHelpdesk");
        }
        if (ACTION_ASSERT.equals(action)) {
            try {
                service.finishAssertion(m_Request.getParameter(PARAM_RESPONSE));
            } catch (CeremonyFailedException e) {
                logWarning("Passkey confirmation failed for " + agent + ": " + e.getMessage());
                return showHelpdesk(service, state, e.messageKey());
            }
            return showHelpdesk(service, state, null);
        }
        if (!service.recentlyVerified()) {
            return showHelpdesk(service, state, null);
        }
        if ((ACTION_ISSUE.equals(action) || ACTION_DONE.equals(action))
                && !state.checkActionToken(m_Request.getParameter(PARAM_TOKEN))) {
            logWarning("Helpdesk request with a bad token for " + agent + ", action=" + action);
            return showHelpdesk(service, state, "error.expired");
        }
        if (ACTION_DONE.equals(action)) {
            return signIn(state, principal);
        }
        if (ACTION_ISSUE.equals(action)) {
            return issueToken(service, state, principal);
        }
        return showHelpdesk(service, state, null);
    }

    private int issueToken(PasskeyService service, CeremonyState state, NIDPPrincipal agent) {
        for (int i = 1; i <= HELPDESK_CHECKS; i++) {
            if (!"on".equals(m_Request.getParameter("pk_check" + i))) {
                return showHelpdesk(service, state, "error.helpdeskChecks");
            }
        }
        String id = m_Request.getParameter(PARAM_TARGET);
        String target = id == null ? "" : id.trim();
        Optional<UserDirectory.User> user = target.isEmpty() ? Optional.empty() : new NamUserDirectory().byId(target);
        if (!user.isPresent()) {
            return showHelpdesk(service, state, "error.helpdeskNoUser");
        }
        NIDPPrincipal targetPrincipal = (NIDPPrincipal) user.get().principal();
        if (agent.getGuid().equals(targetPrincipal.getGuid())) {
            logWarning("Refused helpdesk token: " + agent.getUserIdentifier() + " asked for their own account");
            return showHelpdesk(service, state, "error.helpdeskSelf");
        }
        Optional<RecoveryStore> recovery = recoveryFor(targetPrincipal);
        if (!recovery.isPresent()) {
            return showError("error.recoveryUnavailable");
        }
        RecoveryStore.IssuedToken token = recovery.get().issueToken(config.enrollTokenTtlSec());
        logInfo("Helpdesk agent " + agent.getUserIdentifier() + " issued a token for "
                + targetPrincipal.getUserIdentifier() + " with all checks confirmed, expiring " + token.expires);
        notifyUser(Notification.HELPDESK_TOKEN_ISSUED, targetPrincipal, null);
        PageToShow page = helpdeskPage(state, null);
        page.addAttribute("pk_issued_token", (Object) token.display);
        page.addAttribute("pk_issued_user", (Object) target);
        page.addAttribute("pk_issued_expires", (Object) EXPIRY.format(token.expires));
        noStore();
        return SHOW_JSP;
    }

    private int showHelpdesk(PasskeyService service, CeremonyState state, String messageKey) {
        if (isFramePageNeeded()) {
            return showFramePage(state, messageKey);
        }
        String message = messageKey != null ? messageKey : state.takePendingMessage().orElse(null);
        if (service.recentlyVerified()) {
            helpdeskPage(state, message);
            return SHOW_JSP;
        }
        if (service.passkeys().isEmpty()) {
            return showError("error.noPasskey");
        }
        PageToShow page = page(config.mfaJsp(), message);
        page.addAttribute("pk_options", (Object) PasskeyMessages.jsonForScriptTag(service.startAssertion()));
        page.addAttribute("pk_intro", PasskeyMessages.get(m_Request.getLocale(), "helpdesk.confirm"));
        return SHOW_JSP;
    }

    private PageToShow helpdeskPage(CeremonyState state, String messageKey) {
        PageToShow page = page(config.helpdeskJsp(), messageKey);
        page.addAttribute("pk_token", (Object) state.actionToken());
        return page;
    }

    /** Fails closed: an unreadable membership list throws and ends the sign-in. */
    private boolean isHelpdeskMember(NIDPPrincipal principal) {
        UserAuthority authority = principal.getAuthority();
        String attribute = authority != null && authority.isActiveDirectory() ? "memberOf" : "groupMembership";
        return PasskeyConfig.isMemberOf(new NamUserAttributes(principal, m_Session).read(attribute),
                config.helpdeskGroupDn());
    }

    /** @return this user's recovery codes and token, if a pepper is configured */
    private Optional<RecoveryStore> recoveryFor(NIDPPrincipal principal) {
        if (principal == null) {
            return Optional.empty();
        }
        return config.recoveryPepper().map(pepper -> new RecoveryStore(
                new NamUserAttributes(principal, m_Session), config.recoveryAttribute(), config.tokenAttribute(),
                config.auxClass(), pepper, principal.getGuid(), config.maxFailed(), Clock.systemUTC()));
    }

    /** Codes for a user's first passkey, if they have none yet and the page can show them right now. */
    private Optional<List<String>> firstRecoveryCodes(NIDPPrincipal principal) {
        if (isFramePageNeeded()) {
            return Optional.empty();
        }
        return recoveryFor(principal)
                .filter(recovery -> recovery.codesLeft() == 0)
                .filter(recovery -> {
                    Optional<Instant> blocked = recovery.codesBlockedUntil(config.recoveryCooldownSec());
                    blocked.ifPresent(until -> logInfo("Held back first recovery codes for "
                            + principal.getUserIdentifier() + " until " + until + ": recovered recently"));
                    return !blocked.isPresent();
                })
                .map(recovery -> {
                    logInfo("First recovery codes generated for " + principal.getUserIdentifier());
                    return recovery.generateCodes(config.recoveryCodeCount());
                });
    }

    private int showCodes(List<String> codes) {
        PageToShow page = page(config.codesJsp(), null);
        page.addAttribute("pk_codes", (Object) codes);
        noStore();
        return SHOW_JSP;
    }

    /** Codes and tokens are shown once; the browser must not keep the page. */
    private void noStore() {
        m_Response.setHeader("Cache-Control", "no-store");
        m_Response.setHeader("Pragma", "no-cache");
    }

    /**
     * Queues an email to the user about a change, if NOTIFY_EMAIL is on. Returns at once: the address
     * is read and the message sent on the notification thread, and nothing here can fail the request.
     */
    private void notifyUser(Notification event, NIDPPrincipal principal, String passkeyName) {
        if (!config.notifyEmail() || principal == null) {
            return;
        }
        try {
            Locale locale = m_Request.getLocale();
            Map<String, String> values = new HashMap<>();
            values.put("name", passkeyName == null ? "" : passkeyName);
            values.put("time", EXPIRY.format(Instant.now()));
            values.put("ip", clientAddress(locale));
            String attribute = config.notifyMailAttribute();
            // Read later, off the request thread; without the session, which belongs to this request
            NOTIFIER.submit(event, principal.getUserIdentifier(),
                    () -> new NamUserAttributes(principal, null).read(attribute), values, locale);
        } catch (RuntimeException e) {
            logWarning("Couldn't queue the '" + event.key + "' email for " + principal.getUserIdentifier() + ": " + e);
        }
    }

    private String clientAddress(Locale locale) {
        try {
            String address = m_Session.getClientRealIPAddress();
            if (address != null && !address.trim().isEmpty()) {
                return address.trim();
            }
        } catch (RuntimeException e) {
            logFine("Client address unavailable: " + e);
        }
        return PasskeyMessages.get(locale, "notify.unknownAddress");
    }

    private int signIn(CeremonyState state, NIDPPrincipal principal) {
        state.clear();
        setPrincipal(principal);
        return AUTHENTICATED;
    }

    /** What the user should see now, given their passkeys and this login's progress. */
    private int showCurrentPage(PasskeyService service, CeremonyState state, String messageKey) {
        if (isFramePageNeeded()) {
            return showFramePage(state, messageKey);
        }
        String message = messageKey != null ? messageKey : state.takePendingMessage().orElse(null);
        if (state.enrolling()) {
            return showSavedPage(null, message);
        }
        List<PasskeyRecord> passkeys = service.passkeys();
        if (!passkeys.isEmpty()) {
            return showAssert(service, message);
        }
        if (service.mayRegister(passkeys)) {
            return showRegister(service, state, message);
        }
        return showError("error.noPasskey");
    }

    private int showAssert(PasskeyService service, String messageKey) {
        PageToShow page = page(config.mfaJsp(), messageKey);
        page.addAttribute("pk_options", (Object) PasskeyMessages.jsonForScriptTag(service.startAssertion()));
        return SHOW_JSP;
    }

    private int showRegister(PasskeyService service, CeremonyState state, String messageKey) {
        if (isFramePageNeeded()) {
            return showFramePage(state, messageKey);
        }
        try {
            String options = service.startRegistration();
            PageToShow page = page(config.registerJsp(), messageKey);
            page.addAttribute("pk_state", STATE_REGISTER);
            page.addAttribute("pk_options", (Object) PasskeyMessages.jsonForScriptTag(options));
            page.addAttribute("pk_max_name", Integer.toString(PasskeyService.MAX_NAME_LENGTH));
            if (config.mode() == PasskeyConfig.Mode.MANAGE || state.recoveryEnrolled()) {
                page.addAttribute("pk_cancel", Boolean.TRUE);
            }
            return SHOW_JSP;
        } catch (CeremonyFailedException e) {
            logWarning("Cannot start passkey registration: " + e.getMessage());
            if (config.mode() == PasskeyConfig.Mode.MANAGE || state.recoveryEnrolled()) {
                return showManage(service, state, e.messageKey());
            }
            return e.messageKey().equals("error.limit") && state.enrolling()
                    ? showSavedPage(null, e.messageKey())
                    : showError(e.messageKey());
        }
    }

    private int showSaved(CeremonyState state, String savedName) {
        if (isFramePageNeeded()) {
            return showFramePage(state, null);
        }
        return showSavedPage(savedName, null);
    }

    private int showSavedPage(String savedName, String messageKey) {
        PageToShow page = page(config.registerJsp(), messageKey);
        page.addAttribute("pk_state", STATE_SAVED);
        if (savedName != null) {
            page.addAttribute("pk_saved_name", savedName);
        }
        return SHOW_JSP;
    }

    private PageToShow page(String jsp, String messageKey) {
        m_PageToShow = new PageToShow(jsp);
        m_PageToShow.addAttribute("url", getReturnURL());
        m_PageToShow.addAttribute("pk_fallback", fallbackUrl());
        m_PageToShow.addAttribute("pk_recovery_url", config.recoveryUrl());
        if (messageKey != null) {
            m_PageToShow.addAttribute("pk_message", PasskeyMessages.get(m_Request.getLocale(), messageKey));
        }
        return m_PageToShow;
    }

    /**
     * Where "Use another way to sign in" goes: the configured contract, or on the passwordless page
     * NAM's default contract when none is set. Elsewhere the user has already given a password, and
     * the default contract (usually password only) would let them skip the passkey, so there's no
     * link unless one is configured. PASSKEY_ONLY hides it everywhere.
     */
    private String fallbackUrl() {
        String configured = config.fallbackContractUrl();
        if (!configured.isEmpty() || config.passkeyOnly() || config.mode() != PasskeyConfig.Mode.LOGIN) {
            return configured;
        }
        try {
            AuthenticationContract contract = NIDPContext.getNIDPContext().getAuthenticationManager()
                    .getDefaultContract(false);
            if (contract == null || !contract.isDefault() || contract.getCard() == null
                    || contract.getUri().equalsIgnoreCase(getContractURI())) {
                return "";
            }
            String id = contract.getCard().getID(true);
            String sid = m_SessionData == null ? null : m_SessionData.getID();
            return m_Request.getContextPath() + "/jsp/main.jsp?id=" + URLEncoder.encode(id, StandardCharsets.UTF_8)
                    + (sid == null ? "" : "&sid=" + URLEncoder.encode(sid, StandardCharsets.UTF_8));
        } catch (RuntimeException | LinkageError e) {
            // NAM's own classes; without them the page simply has no fallback link
            logFine("No default contract for the fallback link: " + e);
            return "";
        }
    }

    /**
     * Without {@code uiDestination=contentDiv} NAM wants the outer login page, which then asks for
     * the content in a second request. No challenge is issued for this first pass.
     */
    private boolean isFramePageNeeded() {
        return getJSPForBranding() != null;
    }

    private int showFramePage(CeremonyState state, String messageKey) {
        if (messageKey != null) {
            state.setPendingMessage(messageKey);
        }
        m_PageToShow = new PageToShow(getJSPForBranding());
        m_PageToShow.addAttribute("url", getReturnURL());
        return SHOW_JSP;
    }

    private int showError(String messageKey) {
        m_PageToShow = new PageToShow("err");
        m_Request.setAttribute(NIDPConstants.ATTR_ERR, PasskeyMessages.get(m_Request.getLocale(), messageKey));
        return SHOW_PAGE_TERMINATE;
    }

    private NIDPPrincipal principalFromPreviousMethod() {
        NIDPPrincipal principal = (NIDPPrincipal) m_Properties.get("Principal");
        if (principal != null) {
            return principal;
        }
        boolean signedIn = m_Session.isAuthenticated() || m_SessionData.getAuthnChainState() != null;
        return signedIn && m_Session.getSubject() != null ? m_Session.getSubject().getPrincipal() : null;
    }

    private static UserAccount accountFor(NIDPPrincipal principal) {
        String name = principal instanceof LDAPPrincipal ? ((LDAPPrincipal) principal).getUserName() : null;
        if (name == null || name.isEmpty()) {
            name = principal.getUserIdentifier();
        }
        return new UserAccount(principal.getGuid(), name, principal.getFullName());
    }

    private CeremonyState.Session sessionProperties() {
        return new CeremonyState.Session() {
            @Override
            public Object get(String key) {
                return m_Session.getSessionProperty(key);
            }

            @Override
            public void put(String key, Object value) {
                m_Session.setSessionProperty(key, value);
            }
        };
    }

    /** Keeps two passkey methods in one session from sharing state. */
    private String scope() {
        String id = getProperty("id");
        return id == null || id.isEmpty() ? "default" : id;
    }

    private static void logFine(String message) {
        if (NIDPLog.isLoggableAppFine()) {
            NIDPLog.logAppFine(LOG_PREFIX + LogText.clean(message));
        }
    }

    private static void logInfo(String message) {
        if (NIDPLog.isLoggableAppInfo()) {
            NIDPLog.logAppInfo(LOG_PREFIX + LogText.clean(message));
        }
    }

    private static void logWarning(String message) {
        if (NIDPLog.isLoggableAppWarning()) {
            NIDPLog.logAppWarning(LOG_PREFIX + LogText.clean(message));
        }
    }

    private static String version() {
        String version = PasskeyAuthClass.class.getPackage().getImplementationVersion();
        return version == null ? "(dev)" : version;
    }
}
