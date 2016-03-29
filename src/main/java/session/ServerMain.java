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
            System.out.println("serverPublicKey: " + serverPublicKey);
            RSAPrivateKey serverPrivateKey = (RSAPrivateKey) serverKeyPair.getPrivate();

            // Send public key to server
            serverSession.sendRSAPublicKey((RSAPublicKey) serverKeyPair.getPublic());

            // Retrieve server public key
            RSAPublicKey clientPublicKey = serverSession.retrieveRSAPublicKey();

            // Fetch the message from the client
            byte[] receivedMessage = serverSession.pollForMessage();
            System.out.println("Public key length: " + serverPublicKey.getModulus().bitLength()/8);
            byte[] encryptedKey = Arrays.copyOfRange(receivedMessage, 0, serverPublicKey.getModulus().bitLength()/8);
            byte[] AESKeyByteArray = RSA.decrypt(encryptedKey, serverPrivateKey, RSA_TRANSFORMATION);
            System.out.println("receivedMessage: " +Base64.getEncoder().encodeToString(receivedMessage));
            System.out.println("encryptedKey: " + Base64.getEncoder().encodeToString(encryptedKey));
            System.out.println("AESKeyByteArray: " + Base64.getEncoder().encodeToString(AESKeyByteArray));
            Key AESKey = new SecretKeySpec(AESKeyByteArray, 0, AESKeyByteArray.length, "AES");
            System.out.println("Received AES key: " + AESKey.toString());

            // Get the number of bits in the
            int AESKeyBitsStartIndex = serverPublicKey.getModulus().bitLength()/8;
            ByteBuffer byteBuffer = ByteBuffer.wrap(Arrays.copyOfRange(receivedMessage, AESKeyBitsStartIndex, AESKeyBitsStartIndex + 4));
            int AESKeyBits = byteBuffer.getInt();
            System.out.println("AESKeyBits: " + AESKeyBits);
            System.out.println("AESKey: " + Base64.getEncoder().encodeToString(AESKey.getEncoded()));

            int IVStartIndex = AESKeyBitsStartIndex + 4;
            byte[] iv = Arrays.copyOfRange(receivedMessage, IVStartIndex, IVStartIndex + AESKeyBits);
            System.out.println("iv: " +Base64.getEncoder().encodeToString(iv));

            int encryptedDataStartIndex = IVStartIndex + AESKeyBits;
            byte[] encryptedData = Arrays.copyOfRange(receivedMessage, encryptedDataStartIndex, receivedMessage.length);
            System.out.println("encryptedData: " +Base64.getEncoder().encodeToString(encryptedData));

            byte[] unencryptedData = AES.decrypt(encryptedData, AESKey, AES_TRANSFORMATION, iv);
            System.out.println("unencryptedData: " +Base64.getEncoder().encodeToString(unencryptedData));
            byte[] unzipedData = ZIP.decompress(unencryptedData);
            System.out.println("unzipedData: " +Base64.getEncoder().encodeToString(unzipedData));

            byteBuffer = ByteBuffer.wrap(Arrays.copyOfRange(unzipedData, 0, 4));
            int signatureLength = byteBuffer.getInt();

            System.out.println("signatureLength: " + signatureLength);
            byte[] signature = Arrays.copyOfRange(unzipedData, 4, 4 + signatureLength);

            byte[] messageSection = Arrays.copyOfRange(unzipedData, 4 + signatureLength, unzipedData.length);
            if(!DigitalSignature.verifySignature(messageSection, signature, clientPublicKey, SIGNATURE_TRANSFORMATION)) {
                System.out.println("Signature does not match, ignoring message");
                // TODO: do something more sensical here
                return;
            }

            byte[] nonce = Arrays.copyOfRange(messageSection, 0, 8);
            System.out.println("nonce: " +Base64.getEncoder().encodeToString(nonce));

            // This should be 0 in this case
            byte[] messageContents = Arrays.copyOfRange(messageSection, 8, messageSection.length);
            System.out.println(new String(messageContents, "UTF8"));

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
