package encryption;


import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.util.*;

import static java.lang.Thread.sleep;

public class ClientMain {
    public static void main(String[] args) {
        try {
            ClientSession clientSession = new ClientSession();
            Set<BigInteger> usedNonces = new HashSet<>();
            Key AESKey = AES.generateKey(128);
            System.out.println("Generated AES Key: " + AESKey.toString());
            System.out.println("AES key byte array: " + AESKey.getEncoded());
            System.out.println("AES key byte array length: " + AESKey.getEncoded().length);
            String encodedAESKey = Base64.getEncoder().encodeToString(AESKey.getEncoded());
            System.out.println("Sending AES key encoded as Base64: " + encodedAESKey);

            // TODO: The Key is still in plaintext, it should be encrypted with the public key of server
            // TODO: Generate a NONCE and encrypt it with the AES key
            clientSession.sendMessage(encodedAESKey);

            byte[] nonceByteArray = clientSession.pollForMessage();

            // TODO: Decrypt the nonce
            BigInteger nonce = new BigInteger(nonceByteArray);
            usedNonces.add(nonce);
            System.out.println(nonce);





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
        }
    }
}
