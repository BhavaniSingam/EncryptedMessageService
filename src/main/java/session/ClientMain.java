package session;

import encryption.AES;
import encryption.RSA;
import signature.DigitalSignature;
import storage.STORE;
import storage.StoreKeys;
import zipping.ZIP;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static session.Session.*;

/**
 * Contains main for the client
 *
 * @author Brian Mc George
 */
public class ClientMain {
    private static final int AES_KEY_LENGTH = 128;

    public static void main(String[] args) {
        try {

            ClientSession clientSession = new ClientSession();
            Set<String> usedNonces = new HashSet<>();
            SecureRandom IVSecureRandom = new SecureRandom();
            SecureRandom saltSecureRandom = new SecureRandom();

            // ========== RSA key exchange ==========
            // Read 2048 bit keys from storage
            KeyPair readKeyPair = STORE.readKeysFromPrivateKeyRing(-7975117869850543847L, StoreKeys.CLIENT_KEYS_FOLDER + StoreKeys.PRIVATE_KEY_RING_FILE_NAME);
            RSAPublicKey clientPublicKey = (RSAPublicKey) readKeyPair.getPublic();
            RSAPrivateKey clientPrivateKey = (RSAPrivateKey) readKeyPair.getPrivate();

            // Read server public key from file
            RSAPublicKey serverPublicKey = (RSAPublicKey) STORE.readKeyFromPublicKeyRing(5919969100937786679L, StoreKeys.CLIENT_KEYS_FOLDER + StoreKeys.PUBLIC_KEY_RING_FILE_NAME);

            // ========== AES key exchange ==========
            // Generate AES key
            Key AESKey = AES.generateKey(AES_KEY_LENGTH);
            System.out.println("Generated an AES key of " + AESKey.getEncoded().length * 8 + " bits");
            System.out.println("AES key (visualised as a base64 string): " + Base64.getEncoder().encodeToString(AESKey.getEncoded()));

            // Encrypt the AES key
            byte[] encryptedKey = RSA.encrypt(AESKey.getEncoded(), serverPublicKey, RSA_TRANSFORMATION);
            System.out.println("Encrypted AES key with server public key, length of encrypted key is " + encryptedKey.length * 8 + " bits");
            System.out.println("Encrypted AES key (Base64): " + Base64.getEncoder().encodeToString(encryptedKey));

            // Generate random salt - this can be sent as plaintext
            byte[] iv = AES.generateIV(saltSecureRandom, AES_KEY_LENGTH);
            System.out.println("Random salt generated (visualised as a base64 string): " + Base64.getEncoder().encodeToString(iv));

            // Generate a nonce
            byte[] nonce;
            String nonceTxt;
            do {
                nonce = AES.generateIV(IVSecureRandom, 64);
                nonceTxt = Base64.getEncoder().encodeToString(nonce);
            } while (usedNonces.contains(nonceTxt));
            usedNonces.add(nonceTxt);
            System.out.println("64 bit nonce generated (visualised as base64): " + nonceTxt);

            // ========== Hello Message ==========
            String text = "PGP Hello";
            byte[] clientMessage = text.getBytes("UTF8");
            System.out.println("Sending an initial hello message: " + text);

            // ========== Message contents ==========
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(nonce);
            outputStream.write(clientMessage);
            byte[] messageContents = outputStream.toByteArray();
            System.out.println("Message contents (Nonce and message), visualised as base64 string: " + Base64.getEncoder().encodeToString(messageContents));

            // ========== Signature ==========
            byte[] signature = DigitalSignature.generateSignature(messageContents, clientPrivateKey, SIGNATURE_TRANSFORMATION);
            System.out.println("Signature has " + signature.length + " bits");
            System.out.println("Signature (visualised as base64 String): " + Base64.getEncoder().encodeToString(signature));

            // ========== Concatenate signature and message ==========
            outputStream.reset();
            ByteBuffer byteBuffer = ByteBuffer.allocate(4);
            byteBuffer.putInt(signature.length);
            outputStream.write(byteBuffer.array());
            outputStream.write(signature);

            outputStream.write(messageContents);

            byte[] concatenatedSignatureAndMessage = outputStream.toByteArray();
            System.out.println("Concatenated signature and message (Base64): " + Base64.getEncoder().encodeToString(concatenatedSignatureAndMessage));
            System.out.println("Before zipping length: " + concatenatedSignatureAndMessage.length);
            byte[] zippedMessage = ZIP.compress(concatenatedSignatureAndMessage);
            System.out.println("After zipping length: " + zippedMessage.length);
            System.out.println("Zipped message (Base64): " + Base64.getEncoder().encodeToString(zippedMessage));

            byte[] encryptedMessage = AES.encrypt(zippedMessage, AESKey, AES_TRANSFORMATION, iv);
            System.out.println("Encrypted message (Base64): " + Base64.getEncoder().encodeToString(encryptedMessage));

            // ========== Final message construction ==========
            outputStream.reset();

            // Include the length of the salt
            byteBuffer = ByteBuffer.allocate(4);
            byteBuffer.putInt(iv.length);

            outputStream.write(encryptedKey);
            outputStream.write(byteBuffer.array());
            outputStream.write(iv);
            outputStream.write(encryptedMessage);
            byte[] output = outputStream.toByteArray();

            clientSession.sendMessage(output);

            // ========== Threads to allow sending and receiving of messages ==========
            Thread sendThread = new Thread() {
                public void run() {
                    while (true) {
                        String message = null;
                        try {
                            message = clientSession.captureUserInput();
                            byte[] sendMessage = message.getBytes("UTF8");
                            System.out.println("Sending message from client: " + message);
                            clientSession.sendMessage(AES_KEY_LENGTH, IVSecureRandom, saltSecureRandom, clientPrivateKey, AESKey, usedNonces, sendMessage);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            };

            Thread receiveThread = new Thread() {
                public void run() {
                    while (true) {
                        try {
                            byte[][] messages = clientSession.fetchMessages(AES_KEY_LENGTH, AESKey, serverPublicKey, usedNonces);
                            for (byte[] message : messages) {
                                if (message != null) {
                                    System.out.println(new String(message, "UTF8"));
                                }
                            }
                            sleep(SLEEP_TIME);
                        } catch (IOException | InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                }
            };

            receiveThread.start();
            sendThread.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
