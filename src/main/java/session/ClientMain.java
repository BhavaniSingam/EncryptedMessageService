package session;


import encryption.AES;
import encryption.RSA;
import signature.DigitalSignature;
import storage.STORE;
import storage.StoreKeys;
import zipping.ZIP;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static java.lang.Thread.sleep;
import static session.Session.AES_TRANSFORMATION;
import static session.Session.RSA_TRANSFORMATION;
import static session.Session.SIGNATURE_TRANSFORMATION;

public class ClientMain {
    private static final int AES_KEY_LENGTH = 128;

    public static void main(String[] args) {
        try {

            ClientSession clientSession = new ClientSession();
            Set<BigInteger> usedNonces = new HashSet<>();
            SecureRandom secureRandom = new SecureRandom();
            SecureRandom IVSecureRandom = new SecureRandom();

            // ========== RSA key exchange ==========
            // Read 2048 bit keys from storage
            RSAPublicKey clientPublicKey = (RSAPublicKey) STORE.readPublicKeyFromFile(StoreKeys.CLIENT_KEYS_FOLDER + StoreKeys.CLIENT_PUBLIC_KEY_FILE_NAME);
            RSAPrivateKey clientPrivateKey = (RSAPrivateKey) STORE.readPrivateKeyFromFile(StoreKeys.CLIENT_KEYS_FOLDER + StoreKeys.CLIENT_PRIVATE_KEY_FILE_NAME);

            // Send public key to server
            clientSession.sendRSAPublicKey(clientPublicKey);

            // Retrieve server public key
            RSAPublicKey serverPublicKey = clientSession.retrieveRSAPublicKey();

            // ========== AES key exchange ==========
            // Generate AES key
            Key AESKey = AES.generateKey(AES_KEY_LENGTH);
            System.out.println("Generated an AES key of " + AESKey.getEncoded().length * 8 + " bits");
            System.out.println("AES key (visualised as a base64 string): " + Base64.getEncoder().encodeToString(AESKey.getEncoded()));

            // Encrypt the AES key
            byte[] encryptedKey = RSA.encrypt(AESKey.getEncoded(), serverPublicKey, RSA_TRANSFORMATION);
            System.out.println("Encrypted AES key with server public key, length of encrypted key is " + encryptedKey.length*8 + " bits");
            System.out.println("Encrypted AES key (Base64): " + Base64.getEncoder().encodeToString(encryptedKey));

            // Generate random salt - this can be sent as plaintext
            byte[] iv = AES.generateIV(AES_KEY_LENGTH);
            System.out.println("Random salt generated (visualised as a base64 string): " + Base64.getEncoder().encodeToString(iv));

            // Encrypt the nonce
            byte[] nonce = AES.generateIV(IVSecureRandom, 64);
            System.out.println("64 bit nonce generated (visualised as base64): " + Base64.getEncoder().encodeToString(nonce));

            // ========== Hello Message ==========
            String text = "PGP Hello";
            byte[] clientMessage = text.getBytes("UTF8");
            System.out.println("Sending an initial hello message: " + text);

            // ========== Message contents ==========
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(nonce);
            outputStream.write(clientMessage);
            byte[] messageContents =outputStream.toByteArray();
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

            byteBuffer = ByteBuffer.allocate(4);
            byteBuffer.putInt(iv.length);

            outputStream.write(encryptedKey);
            outputStream.write(byteBuffer.array());
            outputStream.write(iv);
            outputStream.write(encryptedMessage);
            byte[] output = outputStream.toByteArray();

            clientSession.sendMessage(output);

            // TODO: Add this process for all newly sent messages
            // TODO: Allow one to receive messages back from the server
            // ========== Message sending and receiving ==========
            byte[] receivedMessage = clientSession.pollForMessage();

            while(true) {
                String message = clientSession.captureUserInput();
                clientSession.sendMessage(message);
                // General test for byte array:
                clientSession.sendMessage("TestStringToBytes".getBytes());
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
