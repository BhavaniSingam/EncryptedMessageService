package encryption;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * <h1>RSA Encryption</h1>
 * RSA class contains static methods to generate symmetric key, encrypt and decrypt data
 * @author Michael Kyeyune
 * @since 2016-03-28
 */
public class RSA
{
    /**
     * This method generates RSA key pair.
     * @param keySize The size of the key e.g 1024
     * @return The key pair generated
     */
    public static KeyPair generateKeyPair(int keySize)
    {
        KeyPair keyPair = null;

        try
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySize);
            keyPair = keyGen.generateKeyPair();
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        finally
        {
            return keyPair;
        }
    }

    /**
     * This method encrypts data.
     * @param plainData The data to be encrypted.
     * @param publicKey The public key utilised for encryption.
     * @param transformation The transformation description e.g "RSA/ECB/PKCS1Padding".
     * @return The encrypted data.
     */
    public static byte[] encrypt(byte[] plainData, Key publicKey, String transformation)
    {
        return modify(Cipher.ENCRYPT_MODE, plainData, publicKey, transformation);
    }

    /**
     * This method decrypts data.
     * @param encryptedData The data to be decrypted.
     * @param privateKey The private key utilised for decryption
     * @param transformation The transformation description e.g "RSA/ECB/PKCS1Padding"
     * @return The decrypted data.
     */
    public static byte[] decrypt(byte[] encryptedData, Key privateKey, String transformation)
    {
        return modify(Cipher.DECRYPT_MODE, encryptedData, privateKey, transformation);
    }

    /*
     * This method modifies the data (encrypt or decrypt) according to the mode provided.
     * @param mode The mode to modify the data in i.e Cipher.DECRYPT_MODE or Cipher.ENCRYPT_MODE
     * @param data The data to be modified
     * @param key The key utilised in modifying the data
     * @param transformation The transformation description e.g "RSA/ECB/PKCS1Padding"
     * @return The modified data.
     */
    private static byte[] modify(int mode, byte[] data, Key key, String transformation)
    {
        byte[] modifiedData = null;

        try
        {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(mode, key);
            modifiedData = cipher.doFinal(data);
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        catch (NoSuchPaddingException e)
        {
            e.printStackTrace();
        }
        finally
        {
            return modifiedData;
        }
    }
}
