package session;


import encryption.AES;
import encryption.RSA;
import signature.DigitalSignature;
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
    private static final int RSA_KEY_LENGTH = 2048;

    public static void main(String[] args) {
        try {

            ClientSession clientSession = new ClientSession();
            Set<BigInteger> usedNonces = new HashSet<>();
            SecureRandom secureRandom = new SecureRandom();
            SecureRandom IVSecureRandom = new SecureRandom();

            // ========== RSA key exchange ==========
            // Generate 2048 bit RSA key pair
            KeyPair clientKeyPair = RSA.generateKeyPair(RSA_KEY_LENGTH);
            RSAPublicKey clientPublicKey = (RSAPublicKey) clientKeyPair.getPublic();
            RSAPrivateKey clientPrivateKey = (RSAPrivateKey) clientKeyPair.getPrivate();

            // Send public key to server
            clientSession.sendRSAPublicKey((RSAPublicKey) clientKeyPair.getPublic());

            // Retrieve server public key
            RSAPublicKey serverPublicKey = clientSession.retrieveRSAPublicKey();

            // ========== AES key exchange ==========
            // Generate AES key
            Key AESKey = AES.generateKey(AES_KEY_LENGTH);
            System.out.println("Generated AES Key length: " + AESKey.getEncoded().length);
            System.out.println("AESKey: " + Base64.getEncoder().encodeToString(AESKey.getEncoded()));

            // TODO: The Key is still in plaintext, it should be encrypted with the public key of server
            // Encrypt the AES key
            System.out.println("serverPublicKey: " + serverPublicKey);
            byte[] encryptedKey = RSA.encrypt(AESKey.getEncoded(), serverPublicKey, RSA_TRANSFORMATION);
            System.out.println("Encrypted AES key length: " + encryptedKey.length);

            // Generate random salt - this can be sent as plaintext
            byte[] iv = AES.generateIV(AES_KEY_LENGTH);
            System.out.println("ivByteArray: " + Base64.getEncoder().encodeToString(iv));

            // Encrypt the nonce
            byte[] nonce = AES.generateIV(IVSecureRandom, 64);
            System.out.println("nonceByteArray length: " + nonce.length);
            System.out.println("nonce: " + Base64.getEncoder().encodeToString(nonce));

            // Hello message
            byte[] clientMessage = "PGP Hello".getBytes("UTF8");

            // Message contents
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(nonce);
            outputStream.write(clientMessage);
            byte[] messageContents =outputStream.toByteArray();

            // Signature
            byte[] signature = DigitalSignature.generateSignature(messageContents, clientPrivateKey, SIGNATURE_TRANSFORMATION);
            System.out.println("Signature length: " + signature.length);

            // ========== Concatenate signature and message ==========
            outputStream.reset();
            ByteBuffer byteBuffer = ByteBuffer.allocate(4);
            byteBuffer.putInt(signature.length);
            outputStream.write(byteBuffer.array());
            outputStream.write(signature);

            outputStream.write(messageContents);

            byte[] concatenatedSignatureAndMessage = outputStream.toByteArray();
            System.out.println("concatenatedSignatureAndMessage: " + Base64.getEncoder().encodeToString(concatenatedSignatureAndMessage));
            byte[] zippedMessage = ZIP.compress(concatenatedSignatureAndMessage);
            System.out.println("zippedMessage: " + Base64.getEncoder().encodeToString(zippedMessage));

            byte[] encryptedMessage = AES.encrypt(zippedMessage, AESKey, AES_TRANSFORMATION, iv);
            System.out.println("encryptedMessage: " + Base64.getEncoder().encodeToString(encryptedMessage));

            outputStream.reset();
            System.out.println("Encrypted Key:" + Base64.getEncoder().encodeToString(encryptedKey));

            byteBuffer = ByteBuffer.allocate(4);
            byteBuffer.putInt(iv.length);
            System.out.println("ByteBuffer: " + byteBuffer.array().length);

            outputStream.write(encryptedKey);
            outputStream.write(byteBuffer.array());
            outputStream.write(iv);
            outputStream.write(encryptedMessage);
            byte[] output = outputStream.toByteArray();

            clientSession.sendMessage(output);

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
