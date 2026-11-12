package com.pointbluetech.nam.login.passkey;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The WebAuthn ceremonies and the rules around them for one user, free of servlet and NAM types.
 * {@link PasskeyAuthClass} maps requests and pages onto this.
 */
final class PasskeyService {

    static final int MAX_NAME_LENGTH = 64;

    private static final Logger LOG = LoggerFactory.getLogger(PasskeyService.class);
    private static final DateTimeFormatter DEFAULT_NAME_DATE =
            DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);

    private final PasskeyConfig config;
    private final UserAccount account;
    private final PasskeyStore store;
    private final CeremonyState state;
    private final Clock clock;
    private final RelyingParty relyingParty;

    PasskeyService(PasskeyConfig config, UserAccount account, PasskeyStore store, CeremonyState state, Clock clock) {
        this.config = config;
        this.account = account;
        this.store = store;
        this.state = state;
        this.clock = clock;
        this.relyingParty = RelyingPartyFactory.create(config, new LdapCredentialRepository(account, store));
    }

    List<PasskeyRecord> passkeys() {
        return store.load();
    }

    /** @return the options for {@code navigator.credentials.get()} */
    String startAssertion() {
        AssertionRequest request = relyingParty.startAssertion(StartAssertionOptions.builder()
                .username(account.guid())
                .userVerification(config.userVerification())
                .timeout(config.timeoutMs())
                .build());
        try {
            state.put(CeremonyState.Type.ASSERTION, request.toJson());
            return request.toCredentialsGetJson();
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not serialize assertion request", e);
        }
    }

    void finishAssertion(String responseJson) throws CeremonyFailedException {
        String requestJson = state.take(CeremonyState.Type.ASSERTION)
                .orElseThrow(() -> new CeremonyFailedException("error.expired", "No valid assertion challenge"));
        AssertionResult result;
        try {
            result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(AssertionRequest.fromJson(requestJson))
                    .response(PublicKeyCredential.parseAssertionResponseJson(responseJson))
                    .build());
        } catch (AssertionFailedException | IOException | IllegalArgumentException e) {
            throw new CeremonyFailedException("error.verify", "Assertion rejected: " + e.getMessage(), e);
        }
        if (!result.isSuccess() || !account.userHandle().equals(result.getUserHandle())) {
            throw new CeremonyFailedException("error.verify", "Assertion was not valid for this user");
        }
        if (result.isUserVerified()) {
            state.markVerified();
        }
        recordUse(result);
    }

    /** The signature is already verified, so failing to store the counter doesn't fail the login. */
    private void recordUse(AssertionResult result) {
        try {
            store.recordUse(result.getCredentialId(), result.getSignatureCount(), result.isBackedUp(),
                    clock.instant(), config.lastUsedWriteIntervalSec())
                    .ifPresent(name -> LOG.info("Verified passkey '{}' for {}", name, account.name()));
        } catch (PasskeyStoreException e) {
            LOG.warn("Could not record passkey use for {}: {}", account.name(), e.getMessage());
        }
    }

    /**
     * Whether this login may register a passkey: a user with none (when enrollment is on), one who
     * registered their first during this login, or on the manage page, one who just proved a passkey.
     * Checked at both start and finish, because a passkey can appear in between.
     */
    boolean mayRegister(List<PasskeyRecord> existing) {
        return state.enrolling()
                || (existing.isEmpty() && config.enrollIfNone() && pendingGates(existing).isEmpty())
                || recovering()
                || (config.mode() == PasskeyConfig.Mode.MANAGE && recentlyVerified())
                || (config.mode() == PasskeyConfig.Mode.RECOVERY && recentlyVerified());
    }

    /**
     * The checks still to pass before this user's first passkey: none once they have one, or have
     * registered one in this login, or are recovering (recovery is its own check).
     */
    List<PasskeyConfig.EnrollGate> pendingGates(List<PasskeyRecord> existing) {
        if (!existing.isEmpty() || !config.enrollIfNone() || state.enrolling() || recovering()
                || config.mode() == PasskeyConfig.Mode.RECOVERY) {
            return List.of();
        }
        List<PasskeyConfig.EnrollGate> pending = new ArrayList<>();
        for (PasskeyConfig.EnrollGate gate : config.enrollGates()) {
            if (!state.gatePassed(gate.name())) {
                pending.add(gate);
            }
        }
        return pending;
    }

    /** Whether the manage page may show and act. Having a password isn't enough once a passkey exists. */
    boolean manageUnlocked(List<PasskeyRecord> existing) {
        return existing.isEmpty() ? config.enrollIfNone() : recentlyVerified();
    }

    boolean recentlyVerified() {
        return state.verifiedWithin(config.manageMaxAuthAgeSec());
    }

    void rename(String credentialId, String requestedName) throws CeremonyFailedException {
        List<PasskeyRecord> existing = store.load();
        checkManageUnlocked(existing);
        String name = requestedName == null ? "" : cleanName(requestedName);
        if (name.isEmpty()) {
            throw new CeremonyFailedException("error.nameRequired", "Blank passkey name");
        }
        PasskeyRecord target = find(existing, credentialId);
        store.update(records -> {
            List<PasskeyRecord> updated = new ArrayList<>();
            for (PasskeyRecord record : records) {
                updated.add(record.credentialId().equals(target.credentialId()) ? record.withName(name) : record);
            }
            return updated;
        });
        LOG.info("Renamed passkey '{}' to '{}' for {}", target.name(), name, account.name());
    }

    /** @return the removed passkey's name */
    String delete(String credentialId) throws CeremonyFailedException {
        List<PasskeyRecord> existing = store.load();
        checkManageUnlocked(existing);
        PasskeyRecord target = find(existing, credentialId);
        if (config.requireOne() && existing.size() <= 1) {
            throw new CeremonyFailedException("error.lastPasskey", "Refused to remove the last passkey");
        }
        store.update(records -> {
            List<PasskeyRecord> updated = new ArrayList<>(records);
            updated.removeIf(record -> record.credentialId().equals(target.credentialId()));
            return updated;
        });
        LOG.info("Removed passkey '{}' for {}", target.name(), account.name());
        return target.name();
    }

    List<PasskeyView> views(List<PasskeyRecord> records) {
        List<PasskeyView> views = new ArrayList<>();
        for (PasskeyRecord record : records) {
            views.add(new PasskeyView(record));
        }
        return views;
    }

    /** This login is recovering an account and hasn't got its new passkey yet. */
    private boolean recovering() {
        return config.mode() == PasskeyConfig.Mode.RECOVERY && state.recovered() && !state.recoveryEnrolled();
    }

    private void checkManageUnlocked(List<PasskeyRecord> existing) throws CeremonyFailedException {
        if (!manageUnlocked(existing)) {
            throw new CeremonyFailedException("error.confirmFirst", "Passkey was not verified recently");
        }
    }

    private static PasskeyRecord find(List<PasskeyRecord> records, String credentialId) throws CeremonyFailedException {
        for (PasskeyRecord record : records) {
            if (record.credentialId().getBase64Url().equals(credentialId)) {
                return record;
            }
        }
        throw new CeremonyFailedException("error.notFound", "No such passkey");
    }

    /** @return the options for {@code navigator.credentials.create()} */
    String startRegistration() throws CeremonyFailedException {
        checkMayRegister(store.load());
        // User verification is always required to create a passkey, whatever sign-in later asks for
        AuthenticatorSelectionCriteria.AuthenticatorSelectionCriteriaBuilder selection =
                AuthenticatorSelectionCriteria.builder()
                        .residentKey(config.residentKey())
                        .userVerification(UserVerificationRequirement.REQUIRED);
        config.authenticatorAttachment().ifPresent(selection::authenticatorAttachment);
        PublicKeyCredentialCreationOptions request = relyingParty.startRegistration(StartRegistrationOptions.builder()
                .user(UserIdentity.builder()
                        .name(account.name())
                        .displayName(account.displayName())
                        .id(account.userHandle())
                        .build())
                .authenticatorSelection(selection.build())
                .timeout(config.timeoutMs())
                .build());
        try {
            state.put(CeremonyState.Type.REGISTRATION, request.toJson());
            return request.toCredentialsCreateJson();
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not serialize registration request", e);
        }
    }

    PasskeyRecord finishRegistration(String responseJson, String requestedName) throws CeremonyFailedException {
        String requestJson = state.take(CeremonyState.Type.REGISTRATION)
                .orElseThrow(() -> new CeremonyFailedException("error.expired", "No valid registration challenge"));
        checkMayRegister(store.load());

        RegistrationResult result;
        try {
            result = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                    .request(PublicKeyCredentialCreationOptions.fromJson(requestJson))
                    .response(PublicKeyCredential.parseRegistrationResponseJson(responseJson))
                    .build());
        } catch (RegistrationFailedException | IOException | IllegalArgumentException e) {
            throw new CeremonyFailedException("error.verify", "Registration rejected: " + e.getMessage(), e);
        }
        if (!config.allowedAaguids().isEmpty()) {
            String aaguid = result.getAaguid().getHex();
            boolean listed = config.allowedAaguids().contains(aaguid);
            if (!result.isAttestationTrusted() || !listed) {
                throw new CeremonyFailedException("error.authenticatorNotAllowed", "Refused authenticator " + aaguid
                        + ProviderNames.forAaguid(aaguid).map(name -> " (" + name + ")").orElse("") + ": "
                        + (!result.isAttestationTrusted()
                                ? "its attestation (" + result.getAttestationType() + ") isn't from a trusted root"
                                : "not in ALLOWED_AAGUIDS"));
            }
        }
        if (config.residentKey() == ResidentKeyRequirement.REQUIRED && !result.isDiscoverable().orElse(true)) {
            throw new CeremonyFailedException("error.notDiscoverable", "Authenticator made a non-discoverable credential");
        }

        Instant now = clock.instant();
        PasskeyRecord record = PasskeyRecord.fromRegistration(result, account.userHandle(),
                nameOrDefault(requestedName, result.getAaguid().getHex(), now), now, recovering());
        store.update(records -> {
            List<PasskeyRecord> updated = new ArrayList<>(records);
            updated.add(record);
            return updated;
        });
        // Creating it required user verification, so it counts the same as using one
        state.markVerified();
        if (config.mode() == PasskeyConfig.Mode.MFA) {
            state.setEnrolling(true);
        }
        LOG.info("Registered passkey '{}' for {}", record.name(), account.name());
        return record;
    }

    private void checkMayRegister(List<PasskeyRecord> existing) throws CeremonyFailedException {
        if (!mayRegister(existing)) {
            throw new CeremonyFailedException("error.registerNotAllowed", "Registration is not open for this login");
        }
        // Someone recovering may have lost them all; the limit mustn't lock them out
        if (!recovering() && existing.size() >= config.maxPasskeys()) {
            throw new CeremonyFailedException("error.limit", "User already has " + existing.size() + " passkeys");
        }
    }

    private static String nameOrDefault(String requested, String aaguid, Instant now) {
        String name = requested == null ? "" : cleanName(requested);
        if (!name.isEmpty()) {
            return name;
        }
        return ProviderNames.forAaguid(aaguid).orElse("Passkey") + " " + DEFAULT_NAME_DATE.format(now);
    }

    private static String cleanName(String requested) {
        String name = requested.replaceAll("\\p{Cntrl}", " ").trim();
        return name.length() > MAX_NAME_LENGTH ? name.substring(0, MAX_NAME_LENGTH).trim() : name;
    }
}
