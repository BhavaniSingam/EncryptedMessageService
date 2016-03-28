package encryption;

import org.junit.Test;
import sun.misc.BASE64Encoder;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.SecureRandom;

/**
 * <h1>AES Encryption Test</h1>
 * AESTest tests the methods of the AES class.
 * @author Michael Kyeyune
 * @since 2016-03-28
 */
public class AESTest
{
    @Test
    public void encryptionAndDecryptionTest() throws UnsupportedEncodingException
    {
        String sampleText = "Ahem. So this sample text ... like no big deal ... whatevs ...";
        byte[] plainData = sampleText.getBytes("UTF8");

        int keySize = 128;

        Key key = AES.generateKey(128);
        assertNotNull(key);

        //generate bytes for the initialization vector
        byte[] iv = new byte[keySize/8];
        SecureRandom prng = new SecureRandom();
        prng.nextBytes(iv);

        //specify transformation and carry out encryption
        String transformation = "AES/CBC/PKCS5Padding";
        byte[] encryptedData = AES.encrypt(plainData, key, transformation, iv);
        assertNotNull(encryptedData);

        //generate text from the encrypted data
        String encryptedText = (new BASE64Encoder().encode(encryptedData));
        assertFalse(sampleText.equals(encryptedText));

        //carry out decryption
        byte[] decryptedData = AES.decrypt(encryptedData, key, transformation, iv);
        assertNotNull(decryptedData);

        //generate text from the decrypted data
        String decryptedText = new String(decryptedData, "UTF8");
        assertTrue(sampleText.equals(decryptedText));
    }
}
