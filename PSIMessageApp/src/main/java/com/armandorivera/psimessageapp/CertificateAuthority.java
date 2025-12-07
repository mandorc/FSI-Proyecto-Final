/*
 * The MIT License
 *
 * Copyright 2025 armando.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.armandorivera.psimessageapp;

/**
 *
 * @author armando
 */
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import java.security.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;


/**
 * Autoridad certificadora local "MSN INAOE".
 * <p>
 * - Genera un par de llaves RSA para la CA y un certificado X.509 autofirmado.<br>
 * - Emite certificados X.509 para clientes, en modo clásico (solo RSA) o híbrido (RSA + Kyber).<br>
 * - Mantiene una lista de certificados de confianza.
 */
public class CertificateAuthority {

    static {
        // Provider clásico BC (RSA, AES, X.509, etc.)
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        // Provider PQC (Kyber, etc.)
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    private static final String CA_DN = "CN=MSN INAOE, O=MSN INAOE, C=MX";

    private final KeyPair caKeyPair;
    private final X509Certificate caCertificate;
    private final X500Name caSubjectName;

    private final List<X509Certificate> trustedCertificates = new ArrayList<>();

    public CertificateAuthority() {
        try {
            this.caKeyPair = generateRsaKeyPair();
            this.caSubjectName = new X500Name(CA_DN);
            this.caCertificate = createSelfSignedCaCertificate();
            this.trustedCertificates.add(caCertificate);
        } catch (Exception e) {
            throw new RuntimeException("No se pudo inicializar la CA MSN INAOE", e);
        }
    }

    // ====================
    //  Getters básicos
    // ====================

    public String getCaName() {
        return CA_DN;
    }

    public PublicKey getCaPublicKey() {
        return caKeyPair.getPublic();
    }

    public X509Certificate getCaCertificate() {
        return caCertificate;
    }

    public List<X509Certificate> getTrustedCertificates() {
        return Collections.unmodifiableList(trustedCertificates);
    }

    public boolean isTrusted(X509Certificate cert) {
        return trustedCertificates.stream()
                .anyMatch(c -> c.getSerialNumber().equals(cert.getSerialNumber()));
    }

    // ==========================
    //  Registro de nuevos clientes
    // ==========================

    /**
     * Registra un nuevo cliente:
     * <ul>
     *   <li>Genera par de llaves RSA.</li>
     *   <li>Si el modo es HYBRID_PQ, también genera par de llaves Kyber.</li>
     *   <li>Emite un certificado X.509 híbrido (RSA como clave principal, Kyber en extensión opcional).</li>
     *   <li>Añade el certificado a la lista de confianza.</li>
     *   <li>Guarda el material criptográfico en disco vía {@code CertFileUtils}.</li>
     * </ul>
     */
    public Client registerNewClient(String fullName, CryptoMode mode) throws Exception {

        KeyPair rsaPair = generateRsaKeyPair();
        KeyPair kyberPair = null;

        if (mode == CryptoMode.HYBRID_PQ) {
            kyberPair = generateKyberKeyPair();
        }

        X509Certificate clientCert = generateClientCertificateHybrid(
                fullName,
                rsaPair.getPublic(),
                kyberPair != null ? kyberPair.getPublic() : null
        );

        trustedCertificates.add(clientCert);

        Client client = new Client(fullName, mode, rsaPair, kyberPair, clientCert);

        // Guardar certificado y llaves en archivos PEM (certs/)
        // Si aún no tienes esta clase, puedes comentar la línea.
        CertFileUtils.saveClientMaterial(client);

        return client;
    }

    // ====================
    //  Generación de claves
    // ====================

    private KeyPair generateRsaKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private KeyPair generateKyberKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        // Kyber512 es suficiente para un ejemplo; podrías usar Kyber768 según requisitos
        kpg.initialize(KyberParameterSpec.kyber512, new SecureRandom());
        return kpg.generateKeyPair();
    }

    // ====================
    //  Certificado de la CA
    // ====================

    private X509Certificate createSelfSignedCaCertificate() throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000L); // 1 min antes
        Date notAfter  = new Date(now + 365L * 24 * 60 * 60 * 1000L); // 1 año

        BigInteger serial = new BigInteger(64, new SecureRandom());

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caSubjectName,
                serial,
                notBefore,
                notAfter,
                caSubjectName,
                caKeyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(caKeyPair.getPrivate());

        X509CertificateHolder holder = builder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);
    }

    // =======================================
    //  Certificado de cliente (híbrido opcional)
    // =======================================

    /**
     * Genera un certificado X.509 para el cliente:
     * <ul>
     *   <li>Clave pública principal: RSA.</li>
     *   <li>Si {@code kyberPublicKey} no es null, se añade una extensión
     *       {@code subjectAltPublicKeyInfo} con la clave pública Kyber (certificado híbrido).</li>
     *   <li>Firmado por la CA con SHA256withRSA.</li>
     * </ul>
     */
    private X509Certificate generateClientCertificateHybrid(String fullName,
                                                            PublicKey rsaPublicKey,
                                                            PublicKey kyberPublicKey)
            throws Exception {

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60_000L);
        Date notAfter  = new Date(now + 365L * 24 * 60 * 60 * 1000L);

        BigInteger serial = new BigInteger(64, new SecureRandom());
        X500Name subject = new X500Name("CN=" + fullName);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caSubjectName,
                serial,
                notBefore,
                notAfter,
                subject,
                rsaPublicKey
        );

        // Extensión híbrida: clave alternativa Kyber
        if (kyberPublicKey != null) {
            // La clave pública Kyber viene ya en formato SubjectPublicKeyInfo (SPKI) en getEncoded()
            SubjectPublicKeyInfo kyberSpki =
                    SubjectPublicKeyInfo.getInstance(kyberPublicKey.getEncoded());

            SubjectAltPublicKeyInfo altInfo = new SubjectAltPublicKeyInfo(kyberSpki);

            // Recomendado como no crítica (false)
            builder.addExtension(Extension.subjectAltPublicKeyInfo, false, altInfo);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(caKeyPair.getPrivate());

        X509CertificateHolder holder = builder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);
    }
}