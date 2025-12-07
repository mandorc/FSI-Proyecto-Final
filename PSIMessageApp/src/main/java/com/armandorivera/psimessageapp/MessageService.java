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
import com.armandorivera.psimessageapp.Views.MainFrame;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MessageService {

    public static void sendMessage(Client sender, String recipientName, String plaintext) {
        Client recipient = MainFrame.getClientByName(recipientName);
        if (recipient == null) {
            System.err.println("Destinatario no encontrado: " + recipientName);
            return;
        }

        try {
            // 1) Generar clave AES
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey aesKey = kg.generateKey();

            // 2) Cifrar mensaje con AES/GCM
            byte[] iv = new byte[12];
            java.security.SecureRandom random = new java.security.SecureRandom();
            random.nextBytes(iv);

            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

            byte[] ciphertext = aesCipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            String ctBase64 = Base64.getEncoder().encodeToString(ciphertext);

            // Mostrar en consola el ciphertext
            System.out.println("mensaje mandado CT: " + ctBase64);

            // 3) Cifrar la clave AES con la llave pública RSA del destinatario
            PublicKey recipientPub = recipient.getCertificate().getPublicKey();
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPub);
            byte[] encKey = rsaCipher.doFinal(aesKey.getEncoded());

            // 4) Entregar mensaje (simulando red) y descifrar en el receptor
            decryptAndDeliver(sender, recipient, encKey, iv, ciphertext, ctBase64);

        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    private static void decryptAndDeliver(
            Client sender,
            Client recipient,
            byte[] encKey,
            byte[] iv,
            byte[] ciphertext,
            String ctBase64) throws GeneralSecurityException {

        // 1) Descifrar la clave AES con la llave privada RSA del destinatario
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, recipient.getKeyPair().getPrivate());
        byte[] aesKeyBytes = rsaCipher.doFinal(encKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // 2) Descifrar el ciphertext con AES/GCM
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
        byte[] plainBytes = aesCipher.doFinal(ciphertext);
        String decrypted = new String(plainBytes, StandardCharsets.UTF_8);

        // 3) Entregar al frame del destinatario
        MainFrame.deliverMessage(recipient, sender.getName(), decrypted, ctBase64);
    }
}