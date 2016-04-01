package session;

import encryption.AES;
import encryption.RSA;
import signature.DigitalSignature;
import zipping.ZIP;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static java.lang.Thread.sleep;
import static session.Session.*;

public class ServerMain {
    private static final int RSA_KEY_LENGTH = 2048;
    public static void main(String[] args) {
        try {
            ServerSession serverSession = new ServerSession();
            SecureRandom secureRandom = new SecureRandom();
            serverSession.waitForConnection();
            Set<BigInteger> usedNonces = new HashSet<>();

            // ========== RSA key exchange ==========
            // Generate 2048 bit RSA key pair
            KeyPair serverKeyPair = RSA.generateKeyPair(RSA_KEY_LENGTH);
            RSAPublicKey serverPublicKey = (RSAPublicKey) serverKeyPair.getPublic();
            RSAPrivateKey serverPrivateKey = (RSAPrivateKey) serverKeyPair.getPrivate();

            // Send public key to server
            serverSession.sendRSAPublicKey((RSAPublicKey) serverKeyPair.getPublic());

            // Retrieve server public key
            RSAPublicKey clientPublicKey = serverSession.retrieveRSAPublicKey();

            // ========== Fetch the message from the client ==========
            byte[] receivedMessage = serverSession.pollForMessage();
            int encryptedAESKeyLength = serverPublicKey.getModulus().bitLength()/8;
            byte[] encryptedKey = Arrays.copyOfRange(receivedMessage, 0, encryptedAESKeyLength);
            byte[] AESKeyByteArray = RSA.decrypt(encryptedKey, serverPrivateKey, RSA_TRANSFORMATION);
            System.out.println("Received message (Base64): " +Base64.getEncoder().encodeToString(receivedMessage));
            System.out.println("Encrypted AES key (Base64): " + Base64.getEncoder().encodeToString(encryptedKey));
            System.out.println("AES key (Base64): " + Base64.getEncoder().encodeToString(AESKeyByteArray));
            Key AESKey = new SecretKeySpec(AESKeyByteArray, 0, AESKeyByteArray.length, "AES");

            // ========== Salt length ==========
            ByteBuffer byteBuffer = ByteBuffer.wrap(Arrays.copyOfRange(receivedMessage, encryptedAESKeyLength, encryptedAESKeyLength + 4));
            int ivNumberOfBytes = byteBuffer.getInt();
            System.out.println("Number of bits in the random salt (IV): " + ivNumberOfBytes*8);

            // ========== Random Salt ==========
            int IVStartIndex = encryptedAESKeyLength + 4;
            byte[] iv = Arrays.copyOfRange(receivedMessage, IVStartIndex, IVStartIndex + ivNumberOfBytes);
            System.out.println("Random salt (Base64): " + Base64.getEncoder().encodeToString(iv));

            // ========== Encrypted data ==========
            int encryptedDataStartIndex = IVStartIndex + ivNumberOfBytes;
            byte[] encryptedData = Arrays.copyOfRange(receivedMessage, encryptedDataStartIndex, receivedMessage.length);
            System.out.println("Encrypted data (Base64): " +Base64.getEncoder().encodeToString(encryptedData));

            // ========== Decrypt message ==========
            byte[] unencryptedData = AES.decrypt(encryptedData, AESKey, AES_TRANSFORMATION, iv);
            System.out.println("Unencrypted Data (Base64): " +Base64.getEncoder().encodeToString(unencryptedData));
            byte[] unzippedData = ZIP.decompress(unencryptedData);
            System.out.println("Unzipped Data (Base64): " +Base64.getEncoder().encodeToString(unzippedData));

            // ========== Signature length ==========
            byteBuffer = ByteBuffer.wrap(Arrays.copyOfRange(unzippedData, 0, 4));
            int signatureLength = byteBuffer.getInt();
            System.out.println("Signature length: " + signatureLength);

            // ========== Signature and verification ==========
            byte[] signature = Arrays.copyOfRange(unzippedData, 4, 4 + signatureLength);
            byte[] messageSection = Arrays.copyOfRange(unzippedData, 4 + signatureLength, unzippedData.length);
            if(!DigitalSignature.verifySignature(messageSection, signature, clientPublicKey, SIGNATURE_TRANSFORMATION)) {
                System.out.println("Signature does not match, ignoring message");
                // TODO: do something more sensical here
                return;
            }

            // ========== Nonce ==========
            byte[] nonce = Arrays.copyOfRange(messageSection, 0, 8);
            System.out.println("Nonce (Base64): " +Base64.getEncoder().encodeToString(nonce));

            // ========== Message ==========
            byte[] messageContents = Arrays.copyOfRange(messageSection, 8, messageSection.length);
            System.out.println("Message: " + new String(messageContents, "UTF8"));

            // TODO: Add this process for all newly received messages
            // TODO: Allow one to send messages back to the client
            while(true) {
                byte[][] messages = serverSession.fetchMessages();
                for(byte[] message : messages) {
                    System.out.println(Base64.getDecoder().decode(message));
                }
                sleep(SLEEP_TIME);
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
