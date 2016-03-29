package encryption;

import com.google.common.primitives.Longs;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.util.*;

import static encryption.Session.AES_TRANSFORMATION;
import static encryption.Session.SLEEP_TIME;
import static java.lang.Thread.sleep;

public class ServerMain {
    public static void main(String[] args) {
        try {
            ServerSession serverSession = new ServerSession();
            SecureRandom secureRandom = new SecureRandom();
            serverSession.waitForConnection();
            Set<BigInteger> usedNonces = new HashSet<>();

            // Get the AES key from the client
            byte[] aes_keyMessage = serverSession.pollForMessage();
            Key AESKey = new SecretKeySpec(aes_keyMessage, 0, aes_keyMessage.length, "AES");
            System.out.println("Received byte array assumed to be AES key: " + aes_keyMessage);
            System.out.println("Received AES key: " + AESKey.toString());

            // TODO: Decrypt the AES key using server private key
            // TODO: Decrypt Nonce using AES key

            // Generate a nonce
            BigInteger nonce = serverSession.generateNonce(secureRandom, usedNonces);
            byte[] nonceByteArray = nonce.toByteArray();

            // TODO: encrypt the NONCE

            System.out.println("Generated Nonce: " + nonce);
            System.out.println("Nonce Length: " + nonceByteArray.length);
            serverSession.sendMessage(nonceByteArray);

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
        }
    }


}
