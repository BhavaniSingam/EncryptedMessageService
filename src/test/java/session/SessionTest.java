package session;
/**
 * Created by william on 02-04-2016.
 */

import org.junit.Test;
import java.security.*;
import static org.junit.Assert.*;
import encryption.*;
import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class SessionTest {

    @Test
    public void testEncryptionAndDecryption() throws Exception{
        Session aSession = new Session();
        RSA rsa = new RSA();

        String originalMessage = "Testing encryption";
        byte [] original_Message = originalMessage.getBytes("UTF8");
        final int keySize = 128;

        SecureRandom ivRandom = new SecureRandom();
        SecureRandom saltRandom = new SecureRandom();

        KeyPair keyPair = rsa.generateKeyPair(1024);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        Set <String> noncesUsedC = new HashSet<>(); // nonces used by client
        Set <String> noncesUsedS = new HashSet<>(); // nonces used by sever

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        Key aesKey = keyGen.generateKey();

        byte [] encryptedMessage = aSession.encryptMessage(keySize, ivRandom, saltRandom, privateKey, aesKey, noncesUsedC ,original_Message);
        String input = Base64.getEncoder().encodeToString(encryptedMessage);

        byte [] decrypted_Message = aSession.decryptMessage(input, keySize, aesKey, publicKey, noncesUsedS);
        String decryptedMessage = new String(decrypted_Message);

        assertEquals(decryptedMessage, originalMessage);
    }
}
