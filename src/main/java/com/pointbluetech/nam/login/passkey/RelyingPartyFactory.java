package com.pointbluetech.nam.login.passkey;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.attestation.AttestationTrustSource;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Builds the Yubico {@link RelyingParty} from a validated {@link PasskeyConfig}. */
public final class RelyingPartyFactory {

    private static final List<PublicKeyCredentialParameters> ALGORITHMS = supportedAlgorithms();

    private RelyingPartyFactory() {
    }

    /**
     * The library's default list includes algorithms that Java 11 can't verify, and it logs a warning
     * for each of them on every request. EdDSA needs Java 15 or newer.
     */
    private static List<PublicKeyCredentialParameters> supportedAlgorithms() {
        List<PublicKeyCredentialParameters> algorithms = new ArrayList<>();
        algorithms.add(PublicKeyCredentialParameters.ES256);
        try {
            KeyFactory.getInstance("EdDSA");
            algorithms.add(PublicKeyCredentialParameters.EdDSA);
        } catch (NoSuchAlgorithmException e) {
            // Not on this JVM; passkeys overwhelmingly use ES256 anyway
        }
        algorithms.add(PublicKeyCredentialParameters.RS256);
        return Collections.unmodifiableList(algorithms);
    }

    static List<PublicKeyCredentialParameters> algorithms() {
        return ALGORITHMS;
    }

    public static RelyingPartyIdentity identity(PasskeyConfig config) {
        return RelyingPartyIdentity.builder()
                .id(config.rpId())
                .name(config.rpName())
                .build();
    }

    public static RelyingParty create(PasskeyConfig config, CredentialRepository credentials) {
        RelyingParty.RelyingPartyBuilder builder = RelyingParty.builder()
                .identity(identity(config))
                .credentialRepository(credentials)
                .origins(config.origins())
                // Origins are listed exactly; never accept other ports or subdomains implicitly
                .allowOriginPort(false)
                .allowOriginSubdomain(false)
                .preferredPubkeyParams(ALGORITHMS)
                .attestationConveyancePreference(config.attestation())
                // Untrusted attestation still registers here; with ALLOWED_AAGUIDS set, PasskeyService
                // refuses it with a clear message instead of a generic verification failure
                .allowUntrustedAttestation(true)
                .validateSignatureCounter(true);
        if (!config.attestationTrustRoots().isEmpty()) {
            builder.attestationTrustSource(trustSource(config.attestationTrustRoots()));
        }
        return builder.build();
    }

    /**
     * The roots from ATTESTATION_TRUST_ROOTS, for every authenticator. Revocation isn't checked: the
     * nodes may have no route to the vendors' CRLs, and these roots sign attestation, not sign-ins.
     */
    static AttestationTrustSource trustSource(List<X509Certificate> roots) {
        Set<X509Certificate> rootSet = Collections.unmodifiableSet(new HashSet<>(roots));
        return (chain, aaguid) -> AttestationTrustSource.TrustRootsResult.builder()
                .trustRoots(rootSet)
                .enableRevocationChecking(false)
                .build();
    }
}
