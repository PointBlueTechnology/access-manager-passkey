package com.pointbluetech.nam.login.passkey;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.exception.AssertionFailedException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sign-in where the passkey is the only factor (LOGIN mode), free of servlet and NAM types. Either
 * the browser offers any passkey for this site and the response says whose it is, or the user types
 * an ID first and only that user's passkeys count.
 */
final class PasskeyLogin {

    /** Longer than any real ID; don't search the directory for it. */
    private static final int MAX_ID_LENGTH = 256;

    private static final Logger LOG = LoggerFactory.getLogger(PasskeyLogin.class);

    private final PasskeyConfig config;
    private final CeremonyState state;
    private final Clock clock;
    private final LoginCredentialRepository repository;
    private final RelyingParty relyingParty;
    private final UserDirectory directory;

    PasskeyLogin(PasskeyConfig config, UserDirectory directory, CeremonyState state, Clock clock) {
        this.config = config;
        this.directory = directory;
        this.state = state;
        this.clock = clock;
        this.repository = new LoginCredentialRepository(directory, config.recoveryPepper(), config.rpId());
        this.relyingParty = RelyingPartyFactory.create(config, repository);
    }

    /** @return options for {@code navigator.credentials.get()} that accept any passkey for this site */
    String startUsernameless() {
        return start(StartAssertionOptions.builder());
    }

    /**
     * @return options listing this ID's passkeys, or a decoy that looks the same if it has none or
     *         doesn't exist. The caller can't tell which, and neither can the browser's user.
     */
    String startForId(String id) {
        String trimmed = id == null ? "" : id.trim();
        return start(StartAssertionOptions.builder().username(usernameFor(trimmed)));
    }

    private String usernameFor(String id) {
        if (id.isEmpty() || id.length() > MAX_ID_LENGTH) {
            return LoginCredentialRepository.decoyUsername(id);
        }
        // A real user's answer does the same directory work as a decoy's: one search for the ID and
        // one read, here of their passkeys, which the challenge then reuses
        Optional<UserDirectory.User> found = directory.byId(id);
        if (found.isPresent() && !repository.passkeys(found.get()).isEmpty()) {
            repository.remember(found.get());
            return found.get().account().guid();
        }
        return LoginCredentialRepository.decoyUsername(id);
    }

    private String start(StartAssertionOptions.StartAssertionOptionsBuilder options) {
        AssertionRequest request = relyingParty.startAssertion(options
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

    /**
     * Every failure gives the same message, so a response can't be used to learn about an account.
     *
     * @return the user who proved a passkey. The caller must still check the account is allowed to
     *         sign in: no password is checked here, so the directory hasn't had a say yet.
     */
    UserDirectory.User finish(String responseJson) throws CeremonyFailedException {
        String requestJson = state.take(CeremonyState.Type.ASSERTION)
                .orElseThrow(() -> new CeremonyFailedException("error.loginFailed", "No valid assertion challenge"));
        AssertionResult result;
        try {
            result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(AssertionRequest.fromJson(requestJson))
                    .response(PublicKeyCredential.parseAssertionResponseJson(responseJson))
                    .build());
        } catch (AssertionFailedException | IOException | IllegalArgumentException e) {
            throw new CeremonyFailedException("error.loginFailed", "Assertion rejected: " + e.getMessage(), e);
        }
        if (!result.isSuccess() || !result.isUserVerified()) {
            throw new CeremonyFailedException("error.loginFailed", "Assertion was not valid");
        }
        Optional<UserDirectory.User> user = repository.user(result.getUsername());
        if (!user.isPresent()) {
            throw new CeremonyFailedException("error.loginFailed", "User disappeared during sign-in");
        }
        recordUse(user.get(), result);
        return user.get();
    }

    /**
     * The passkey a failed response used, if this site definitely doesn't have it, so the page can
     * ask the user's password manager to forget it. That's only when the response's user handle names
     * a user found in the directory, whose passkeys were read and include others but not this one.
     * Anything less certain is empty: an unknown or missing user handle, a user with no passkeys (as
     * when the method reads the wrong attribute), or a directory that couldn't be read. A passkey
     * that still works must never be reported.
     */
    Optional<String> unregisteredCredential(String responseJson) {
        try {
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential =
                    PublicKeyCredential.parseAssertionResponseJson(responseJson);
            Optional<ByteArray> handle = credential.getResponse().getUserHandle();
            if (!handle.isPresent()) {
                return Optional.empty();
            }
            Optional<UserDirectory.User> user =
                    repository.user(new String(handle.get().getBytes(), StandardCharsets.UTF_8));
            if (!user.isPresent()) {
                return Optional.empty();
            }
            List<PasskeyRecord> passkeys = user.get().store().load();
            boolean registered = passkeys.stream().anyMatch(record -> record.credentialId().equals(credential.getId()));
            return passkeys.isEmpty() || registered ? Optional.empty() : Optional.of(credential.getId().getBase64Url());
        } catch (IOException | RuntimeException e) {
            // Including PasskeyStoreException: unsure means saying nothing
            return Optional.empty();
        }
    }

    /** The signature is already verified, so failing to store the counter doesn't fail the sign-in. */
    private void recordUse(UserDirectory.User user, AssertionResult result) {
        try {
            user.store().recordUse(result.getCredentialId(), result.getSignatureCount(), result.isBackedUp(),
                    clock.instant(), config.lastUsedWriteIntervalSec())
                    .ifPresent(name -> LOG.info("Verified passkey '{}' for {}", name, user.account().name()));
        } catch (PasskeyStoreException e) {
            LOG.warn("Could not record passkey use for {}: {}", user.account().name(), e.getMessage());
        }
    }
}
