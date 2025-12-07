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
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public final class CertFileUtils {

    private CertFileUtils() {
        // clase de utilidades, no instanciable
    }

    /**
     * Guarda el material criptográfico de un cliente en la carpeta "certs":
     *
     * <pre>
     * certs/<nombre>_cert.pem              (certificado X.509)
     * certs/<nombre>_rsa_public_key.pem    (llave pública RSA)
     * certs/<nombre>_rsa_private_key.pem   (llave privada RSA)
     * certs/<nombre>_kyber_public_key.pem  (llave pública Kyber, si HYBRID_PQ)
     * certs/<nombre>_kyber_private_key.pem (llave privada Kyber, si HYBRID_PQ)
     * </pre>
     */
    public static void saveClientMaterial(Client client) throws Exception {
        String baseDir = System.getProperty("user.dir") + File.separator + "certs";
        File dir = new File(baseDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        String safeName = sanitizeName(client.getName());

        // Certificado X.509
        File certFile = new File(dir, safeName + "_cert.pem");
        String pemCert = toPemCertificate(client.getCertificate());
        writeUtf8(certFile, pemCert);

        // Llaves RSA
        KeyPair rsaPair = client.getRsaKeyPair();
        if (rsaPair != null) {
            File rsaPubFile = new File(dir, safeName + "_rsa_public_key.pem");
            File rsaPrivFile = new File(dir, safeName + "_rsa_private_key.pem");

            String pemRsaPub = toPemPublicKey(rsaPair.getPublic());
            String pemRsaPriv = toPemPrivateKey(rsaPair.getPrivate());

            writeUtf8(rsaPubFile, pemRsaPub);
            writeUtf8(rsaPrivFile, pemRsaPriv);
        }

        // Llaves Kyber (solo si el cliente es híbrido y tiene par Kyber)
        KeyPair kyberPair = client.getKyberKeyPair();
        if (kyberPair != null) {
            File kyberPubFile = new File(dir, safeName + "_kyber_public_key.pem");
            File kyberPrivFile = new File(dir, safeName + "_kyber_private_key.pem");

            String pemKyberPub = toPemPublicKey(kyberPair.getPublic());
            String pemKyberPriv = toPemPrivateKey(kyberPair.getPrivate());

            writeUtf8(kyberPubFile, pemKyberPub);
            writeUtf8(kyberPrivFile, pemKyberPriv);
        }
    }

    /**
     * Carga el certificado X.509 de un cliente desde la carpeta "certs".
     * Si el archivo no existe o está corrupto, lanza excepción.
     */
    public static X509Certificate loadClientCertificateFromFile(String clientName) throws Exception {
        String baseDir = System.getProperty("user.dir") + File.separator + "certs";
        String safeName = sanitizeName(clientName);
        File certFile = new File(baseDir, safeName + "_cert.pem");

        if (!certFile.exists()) {
            throw new IOException("No existe el archivo de certificado: " + certFile.getAbsolutePath());
        }

        String pem = Files.readString(certFile.toPath(), StandardCharsets.UTF_8);
        byte[] der = pemToDerCertificate(pem);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    // =======================
    // Helpers de formato PEM
    // =======================

    private static String sanitizeName(String name) {
        return name.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    private static void writeUtf8(File file, String content) throws IOException {
        Files.writeString(file.toPath(), content, StandardCharsets.UTF_8);
    }

    private static String toPemCertificate(X509Certificate cert) throws Exception {
        byte[] encoded = cert.getEncoded();
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes())
                           .encodeToString(encoded);
        return "-----BEGIN CERTIFICATE-----\n" +
                b64 +
                "\n-----END CERTIFICATE-----\n";
    }

    private static String toPemPrivateKey(PrivateKey privateKey) {
        byte[] encoded = privateKey.getEncoded(); // PKCS#8 o formato PQC equivalente
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes())
                           .encodeToString(encoded);
        return "-----BEGIN PRIVATE KEY-----\n" +
                b64 +
                "\n-----END PRIVATE KEY-----\n";
    }

    private static String toPemPublicKey(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded(); // X.509 SubjectPublicKeyInfo o equivalente PQC
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes())
                           .encodeToString(encoded);
        return "-----BEGIN PUBLIC KEY-----\n" +
                b64 +
                "\n-----END PUBLIC KEY-----\n";
    }

    private static byte[] pemToDerCertificate(String pem) {
        String base64 = pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }
}