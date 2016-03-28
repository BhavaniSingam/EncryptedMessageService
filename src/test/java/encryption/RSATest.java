package encryption;

import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * <h1>RSA Encryption Test</h1>
 * RSATest tests the methods of the RSA class.
 * @author Michael Kyeyune
 * @since 2016-03-28
 */
public class RSATest
{
    @Test
    public void encryptionAndDecryptionTest() throws UnsupportedEncodingException
    {
        String sampleText = "Da da da da da Batman!";
        byte[] plainData = sampleText.getBytes("UTF8");

        int keySize = 1024;
        KeyPair keyPair = RSA.generateKeyPair(keySize);
        assertNotNull(keyPair);

        //specify the transformation to be used
        String transformation = "RSA/ECB/PKCS1Padding";
        byte[] encryptedData = RSA.encrypt(plainData, keyPair.getPublic(), transformation);
        assertNotNull(encryptedData);

        //generate text from the encrypted data
        String encryptedText = new String(encryptedData, "UTF8");
        assertFalse(sampleText.equals(encryptedText));

        //carry out decryption
        byte[] decryptedData = RSA.decrypt(encryptedData, keyPair.getPrivate(), transformation);
        assertNotNull(decryptedData);

        //generate text from decrypted data
        String decryptedText = new String(decryptedData, "UTF8");
        assertTrue(sampleText.equals(decryptedText));
    }
}
