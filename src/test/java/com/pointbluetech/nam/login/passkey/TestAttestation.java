package com.pointbluetech.nam.login.passkey;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** A test attestation CA and the certificates it issues to authenticators. */
final class TestAttestation {

    private static final ASN1ObjectIdentifier FIDO_AAGUID = new ASN1ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4");
    private static final Date FROM = Date.from(Instant.parse("2020-01-01T00:00:00Z"));
    private static final Date TO = Date.from(Instant.parse("2045-01-01T00:00:00Z"));
    private static long serial = 1;

    final KeyPair rootKey;
    final X509Certificate root;

    TestAttestation(String name) throws Exception {
        rootKey = ecKey();
        X500Name subject = new X500Name("CN=" + name + " Attestation Root, O=Test, C=US");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, BigInteger.valueOf(serial++),
                FROM, TO, subject, rootKey.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        root = sign(builder, rootKey);
    }

    /** Gives the authenticator an attestation key and a certificate from this root, naming its AAGUID. */
    void attest(VirtualAuthenticator authenticator) throws Exception {
        KeyPair key = ecKey();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(root, BigInteger.valueOf(serial++), FROM, TO,
                new X500Name("CN=Test Key, OU=Authenticator Attestation, O=Test, C=US"), key.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(FIDO_AAGUID, false, new DEROctetString(authenticator.aaguid));
        authenticator.attestationKey = key;
        authenticator.attestationCertificate = sign(builder, rootKey);
    }

    /** As one line, the way it would be pasted into an Administration Console field. */
    String rootPem() throws Exception {
        return "-----BEGIN CERTIFICATE-----" + Base64.getEncoder().encodeToString(root.getEncoded())
                + "-----END CERTIFICATE-----";
    }

    private static KeyPair ecKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder builder, KeyPair issuer) throws Exception {
        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuer.getPrivate())));
    }
}
