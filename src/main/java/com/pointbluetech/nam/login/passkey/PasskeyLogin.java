package com.pointbluetech.nam.login.passkey;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.exception.AssertionFailedException;
import java.io.IOException;
import java.time.Clock;
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
        return directory.byId(id)
                .filter(user -> !user.store().load().isEmpty())
                .map(user -> user.account().guid())
                .orElseGet(() -> LoginCredentialRepository.decoyUsername(id));
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
        state.markVerified(user.get().account().guid());
        recordUse(user.get(), result);
        return user.get();
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
