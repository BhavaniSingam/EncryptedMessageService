package signature;

import encryption.RSA;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * <h1>Digital Signature Test</h1>
 * Tests the functionality of the DigitalSignature class
 * @author Michael Kyeyune
 * @since 2016-03-28
 */
public class DigitalSignatureTest
{
    @Test
    public void signatureTest() throws UnsupportedEncodingException
    {
        String sampleText = "Oh, you think the darkness is your ally, you merely adopted the dark. I was born in it ...";
        byte[] dataToSign = sampleText.getBytes("UTF8");

        //generate key pair
        int keySize = 1024;
        KeyPair keyPair = RSA.generateKeyPair(keySize);
        assertNotNull(keyPair);

        //generate the signature
        String algorithm  = "SHA1WithRSA";
        byte[] signedData = DigitalSignature.generateSignature(dataToSign, keyPair.getPrivate(), algorithm);
        assertNotNull(signedData);

        String signedDataString = new String(signedData, "UTF8");
        assertFalse(sampleText.equals(signedDataString));

        //verify the signature
        boolean signatureVerified = DigitalSignature.verifySignature(dataToSign, signedData, keyPair.getPublic(), algorithm);
        assertTrue(signatureVerified);
    }
}
