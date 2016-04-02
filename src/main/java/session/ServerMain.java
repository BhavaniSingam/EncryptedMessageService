package session;

import encryption.AES;
import encryption.RSA;
import signature.DigitalSignature;
import storage.STORE;
import storage.StoreKeys;
import zipping.ZIP;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static session.Session.*;

/**
 * Contains main for the server
 *
 * @author Brian Mc George
 */
public class ServerMain {
    public static void main(String[] args) {
        try {
            ServerSession serverSession = new ServerSession();
            serverSession.waitForConnection();
            SecureRandom IVSecureRandom = new SecureRandom();
            SecureRandom saltSecureRandom = new SecureRandom();
            Set<String> usedNonces = new HashSet<>();

            // ========== RSA key exchange ==========
            // Read 2048 bit RSA keys from file
            RSAPublicKey serverPublicKey = (RSAPublicKey) STORE.readPublicKeyFromFile(StoreKeys.SERVER_KEYS_FOLDER + StoreKeys.SERVER_PUBLIC_KEY_FILE_NAME);
            RSAPrivateKey serverPrivateKey = (RSAPrivateKey) STORE.readPrivateKeyFromFile(StoreKeys.SERVER_KEYS_FOLDER + StoreKeys
                    .SERVER_PRIVATE_KEY_FILE_NAME);

            // Retrieve server public key
            RSAPublicKey clientPublicKey = (RSAPublicKey) STORE.readPublicKeyFromFile(StoreKeys.SERVER_KEYS_FOLDER + StoreKeys.CLIENT_PUBLIC_KEY_FILE_NAME);

            // ========== Fetch the message from the client ==========
            byte[] receivedMessage = serverSession.pollForMessage();
            int encryptedAESKeyLength = serverPublicKey.getModulus().bitLength() / 8;
            byte[] encryptedKey = Arrays.copyOfRange(receivedMessage, 0, encryptedAESKeyLength);
            byte[] AESKeyByteArray = RSA.decrypt(encryptedKey, serverPrivateKey, RSA_TRANSFORMATION);
            System.out.println("Received message (Base64): " + Base64.getEncoder().encodeToString(receivedMessage));
            System.out.println("Encrypted AES key (Base64): " + Base64.getEncoder().encodeToString(encryptedKey));
            System.out.println("AES key (Base64): " + Base64.getEncoder().encodeToString(AESKeyByteArray));
            Key AESKey = new SecretKeySpec(AESKeyByteArray, 0, AESKeyByteArray.length, "AES");

            // ========== Salt length ==========
            ByteBuffer byteBuffer = ByteBuffer.wrap(Arrays.copyOfRange(receivedMessage, encryptedAESKeyLength, encryptedAESKeyLength + 4));
            int ivNumberOfBytes = byteBuffer.getInt();
            System.out.println("Number of bits in the random salt (IV): " + ivNumberOfBytes * 8);

            // ========== Random Salt ==========
            int IVStartIndex = encryptedAESKeyLength + 4;
            byte[] iv = Arrays.copyOfRange(receivedMessage, IVStartIndex, IVStartIndex + ivNumberOfBytes);
            System.out.println("Random salt (Base64): " + Base64.getEncoder().encodeToString(iv));

            // ========== Encrypted data ==========
            int encryptedDataStartIndex = IVStartIndex + ivNumberOfBytes;
            byte[] encryptedData = Arrays.copyOfRange(receivedMessage, encryptedDataStartIndex, receivedMessage.length);
            System.out.println("Encrypted data (Base64): " + Base64.getEncoder().encodeToString(encryptedData));

            // ========== Decrypt message ==========
            byte[] unencryptedData = AES.decrypt(encryptedData, AESKey, AES_TRANSFORMATION, iv);
            System.out.println("Unencrypted Data (Base64): " + Base64.getEncoder().encodeToString(unencryptedData));
            byte[] unzippedData = ZIP.decompress(unencryptedData);
            System.out.println("Unzipped Data (Base64): " + Base64.getEncoder().encodeToString(unzippedData));

            // ========== Signature length ==========
            byteBuffer = ByteBuffer.wrap(Arrays.copyOfRange(unzippedData, 0, 4));
            int signatureLength = byteBuffer.getInt();
            System.out.println("Signature length: " + signatureLength);

            // ========== Signature and verification ==========
            byte[] signature = Arrays.copyOfRange(unzippedData, 4, 4 + signatureLength);
            byte[] messageSection = Arrays.copyOfRange(unzippedData, 4 + signatureLength, unzippedData.length);
            if (!DigitalSignature.verifySignature(messageSection, signature, clientPublicKey, SIGNATURE_TRANSFORMATION)) {
                System.out.println("Signature does not match, ignoring message");
                return;
            }

            // ========== Nonce ==========
            byte[] nonce = Arrays.copyOfRange(messageSection, 0, 8);
            String nonceTxt = Base64.getEncoder().encodeToString(nonce);
            System.out.println("Nonce (Base64): " + nonceTxt);
            if (usedNonces.contains(nonceTxt)) {
                System.out.println("Nonce has already been used, dropping message");
                return;
            }
            usedNonces.add(nonceTxt);

            // ========== Message ==========
            byte[] messageContents = Arrays.copyOfRange(messageSection, 8, messageSection.length);
            System.out.println("Message: " + new String(messageContents, "UTF8"));

            // ========== Threads to allow sending and receiving of messages ==========
            Thread receiveThread = new Thread() {
                public void run() {
                    while (true) {
                        try {
                            byte[][] messages = serverSession.fetchMessages(AESKeyByteArray.length * 8, AESKey, clientPublicKey, usedNonces);
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

            Thread sendThread = new Thread() {
                public void run() {
                    while (true) {
                        String message = null;
                        try {
                            message = serverSession.captureUserInput();
                            byte[] sendMessage = message.getBytes("UTF8");
                            System.out.println("Sending message from client: " + message);
                            serverSession.sendMessage(AESKeyByteArray.length * 8, IVSecureRandom, saltSecureRandom, serverPrivateKey, AESKey, usedNonces,
                                    sendMessage);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            };

            receiveThread.start();
            sendThread.start();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }


}
