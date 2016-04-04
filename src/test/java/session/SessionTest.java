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
import java.util.Iterator;
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

        // generate key pair
        KeyPair keyPair = rsa.generateKeyPair(1024);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        aSession.setRemotePublicKey(publicKey);
        aSession.setLocalPrivateKey(privateKey);
        assertNotNull(keyPair);

        // used nonces
        Set <String> noncesUsedC = new HashSet<>(); // nonces used by client
        Set <String> noncesUsedS = new HashSet<>(); // nonces used by sever

        // aes key generation
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        aSession.setAESKey(keyGen.generateKey());

        byte [] encryptedMessage = aSession.encryptMessage(ivRandom, noncesUsedC ,original_Message);
        String input = Base64.getEncoder().encodeToString(encryptedMessage);

        byte [] decrypted_Message = aSession.decryptMessage(input, noncesUsedS);
        String decryptedMessage = new String(decrypted_Message);

        assertEquals(decryptedMessage, originalMessage);

    }

    @Test
    public void testReplayMessage() throws Exception{
        Session aSession = new Session();
        RSA rsa = new RSA();

        String originalMessage = "Testing encryption";
        byte [] original_Message = originalMessage.getBytes("UTF8");
        final int keySize = 128;

        SecureRandom ivRandom = new SecureRandom();
        SecureRandom saltRandom = new SecureRandom();

        // generate key pair
        KeyPair keyPair = rsa.generateKeyPair(1024);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        aSession.setRemotePublicKey(publicKey);
        aSession.setLocalPrivateKey(privateKey);
        assertNotNull(keyPair);

        // used nonces
        Set <String> noncesUsedC = new HashSet<>(); // nonces used by client
        Set <String> noncesUsedS = new HashSet<>(); // nonces used by sever

        // aes key generation
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        aSession.setAESKey(keyGen.generateKey());

        byte [] encryptedMessage = aSession.encryptMessage(ivRandom, noncesUsedC ,original_Message);
        String input = Base64.getEncoder().encodeToString(encryptedMessage);

        Iterator iterator = noncesUsedC.iterator();
        String usedNonce = iterator.next().toString();
        noncesUsedS.add(usedNonce);

        byte [] decrypted_Message = aSession.decryptMessage(input, noncesUsedS);
        assertNull(decrypted_Message);

        assertTrue(noncesUsedS.contains(usedNonce));
        assertFalse(!noncesUsedS.contains(usedNonce));
    }

    @Test
    public void testModifiedMessage() throws Exception{
        Session aSession = new Session();
        RSA rsa = new RSA();

        String originalMessage = "Friday is your day off";
        byte [] original_Message = originalMessage.getBytes("UTF8");
        final int keySize = 128;

        SecureRandom ivRandom = new SecureRandom();
        SecureRandom saltRandom = new SecureRandom();

        // generate key pair
        KeyPair keyPair = rsa.generateKeyPair(1024);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        aSession.setRemotePublicKey(publicKey);
        aSession.setLocalPrivateKey(privateKey);
        assertNotNull(keyPair);

        // used nonces
        Set <String> noncesUsedC = new HashSet<>(); // nonces used by client
        Set <String> noncesUsedS = new HashSet<>(); // nonces used by sever

        // aes key generation
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        aSession.setAESKey(keyGen.generateKey());

        byte [] encryptedMessage = aSession.encryptMessage(ivRandom, noncesUsedC ,original_Message);
        String input = Base64.getEncoder().encodeToString(encryptedMessage);

        // assume someone decrypts, modifies and re-sends it.
        byte [] stolen_Message = aSession.decryptMessage(input, noncesUsedS);
        String stolenMessage = new String(stolen_Message);
        System.out.println(stolenMessage);
        String newMessage = "There is a meeting on Friday";
        byte [] new_Message = newMessage.getBytes("UTF8");
        byte [] modifiedEncryptedMessage = aSession.encryptMessage(ivRandom, noncesUsedC ,new_Message);
        // modified encrypted message is sent

        // receiver decrypts modified input..encrypted with sender's key.
        String modifiedInput = Base64.getEncoder().encodeToString(modifiedEncryptedMessage);
        byte [] decrypted_Message = aSession.decryptMessage(modifiedInput, noncesUsedS);
        String decryptedMessage = new String(decrypted_Message);

        System.out.println("Original message: " + originalMessage);
        System.out.println("Decrypted message: " + decryptedMessage);

        assertNotEquals(decryptedMessage, originalMessage);
    }
}
