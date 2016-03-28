package signature;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * <h1>Digital Signature</h1>
 * DigitalSignature contains methods to create a digital signature and verify a digital signature
 * @author Michael Kyeyune
 * @since 2016-03-28
 */
public class DigitalSignature
{
    /**
     * This method signs data with a private key.
     * @param dataToSign The data to sign
     * @param privateKey The private key utilised in signing
     * @param algorithm The algorithm to use for signing e.g "SHA1WithRSA"
     * @return The signature generated
     */
    public static byte[] generateSignature(byte[] dataToSign, PrivateKey privateKey, String algorithm)
    {
        byte[] signature = null;

        try
        {
            Signature sig = Signature.getInstance(algorithm);
            sig.initSign(privateKey);
            sig.update(dataToSign);
            signature = sig.sign();
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        finally
        {
            return signature;
        }
    }

    /**
     * This method verifies the signature on data.
     * @param unsignedData The original data for which the signature was generated
     * @param signedData The data that was signed
     * @param publicKey The public key utilised to verify the signature
     * @param algorithm The algorithm that was used for signing e.g "SHA1WithRSA"
     * @return Whether the signature is verified or not.
     */
    public static boolean verifySignature(byte[] unsignedData, byte[] signedData, PublicKey publicKey, String algorithm)
    {
        boolean verified = false;

        try
        {
            Signature sig = Signature.getInstance(algorithm);
            sig.initVerify(publicKey);
            sig.update(unsignedData);

            verified = sig.verify(signedData);
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        finally
        {
            return verified;
        }
    }
}
