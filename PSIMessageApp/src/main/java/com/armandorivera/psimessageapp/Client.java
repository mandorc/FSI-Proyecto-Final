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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 *
 * @author armando
 */
/**
 * Modelo de cliente del sistema de mensajería.
 * <p>
 * Cada cliente tiene:
 * <ul>
 *   <li>Nombre lógico (alias).</li>
 *   <li>Modo criptográfico (clásico o híbrido PQC).</li>
 *   <li>Par de llaves RSA.</li>
 *   <li>Opcionalmente, par de llaves Kyber (si el modo es HYBRID_PQ).</li>
 *   <li>Certificado X.509 emitido por la CA "MSN INAOE".</li>
 * </ul>
 */
public class Client {

    private final String name;
    private final CryptoMode mode;

    // Claves clásicas (RSA)
    private final KeyPair rsaKeyPair;

    // Claves post-cuánticas (Kyber); pueden ser null si el modo es CLASSIC
    private final KeyPair kyberKeyPair;

    // Certificado X.509 del cliente (RSA como clave principal, opcionalmente híbrido)
    private final X509Certificate certificate;

    public Client(String name,
                  CryptoMode mode,
                  KeyPair rsaKeyPair,
                  KeyPair kyberKeyPair,
                  X509Certificate certificate) {

        this.name = name;
        this.mode = mode;
        this.rsaKeyPair = rsaKeyPair;
        this.kyberKeyPair = kyberKeyPair;
        this.certificate = certificate;
    }

    // ====================
    //  Getters básicos
    // ====================

    public String getName() {
        return name;
    }

    public CryptoMode getMode() {
        return mode;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    // ====================
    //  RSA
    // ====================

    /** Devuelve el par de llaves RSA (por compatibilidad con código antiguo). */
    public KeyPair getKeyPair() {
        return rsaKeyPair;
    }

    public KeyPair getRsaKeyPair() {
        return rsaKeyPair;
    }

    public PublicKey getRsaPublicKey() {
        return rsaKeyPair != null ? rsaKeyPair.getPublic() : null;
    }

    public PrivateKey getRsaPrivateKey() {
        return rsaKeyPair != null ? rsaKeyPair.getPrivate() : null;
    }

    // ====================
    //  Kyber (PQC)
    // ====================

    /**
     * Par de llaves Kyber. Puede ser null si el cliente fue creado
     * en modo clásico (CLASSIC).
     */
    public KeyPair getKyberKeyPair() {
        return kyberKeyPair;
    }

    public PublicKey getKyberPublicKey() {
        return kyberKeyPair != null ? kyberKeyPair.getPublic() : null;
    }

    public PrivateKey getKyberPrivateKey() {
        return kyberKeyPair != null ? kyberKeyPair.getPrivate() : null;
    }

    @Override
    public String toString() {
        return name + " (" + mode.name() + ")";
    }
}