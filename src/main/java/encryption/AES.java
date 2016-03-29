package encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * <h1>AES Encryption</h1>
 * AES class contains static methods to generate asymmetric key, encrypt and decrypt data.
 *
 * @author Michael Kyeyune
 * @since 2016-03-28
 */
public class AES {

    /**
     * This method generates the AES key with the given size
     *
     * @param keySize The size of the key. Options are 128 (recommended), 192 or 256.
     * @return The key generated.
     */
    public static Key generateKey(int keySize) {
        Key key = null;
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keySize);
            key = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } finally {
            return key;
        }
    }

    /**
     * This method generates the Initialisation Vector to be used in AES
     * @param keySize The size of the key to be used.
     * @return byte[] The Initialization Vector
     */
    public static byte[] generateIV(int keySize)
    {
        byte[] iv = new byte[keySize/8];
        SecureRandom prng = new SecureRandom();
        prng.nextBytes(iv);
        return iv;
    }

    /**
     * This method encrypts data.
     *
     * @param plainData      The data to be encrypted
     * @param key            The key used for encryption
     * @param transformation The transformation description e.g "AES/CBC/PKCS7PADDING"
     * @param iv             The Initialization Vector bytes
     * @return The encrypted data
     */
    public static byte[] encrypt(byte[] plainData, Key key, String transformation, byte[] iv) {
        return modify(Cipher.ENCRYPT_MODE, plainData, key, transformation, iv);
    }

    /**
     * This method decrypts data.
     *
     * @param encryptedData  The data to be decrypted
     * @param key            The key used for decryption
     * @param transformation The transformation description e.g "AES/CBC/PKCS7PADDING"
     * @param iv             The Initialization Vector bytes
     * @return The decrypted data
     */
    public static byte[] decrypt(byte[] encryptedData, Key key, String transformation, byte[] iv) {
        return modify(Cipher.DECRYPT_MODE, encryptedData, key, transformation, iv);
    }

    /**
     * This method modifies data (encrypt or decrypt) according to the mode provided.
     *
     * @param mode           The mode to modify the data in i.e Cipher.DECRYPT_MODE or Cipher.ENCRYPT_MODE
     * @param data           The data to be modified
     * @param key            The key utilised in modifying the data
     * @param transformation The transformation description e.g "AES/CBC/PKCS7PADDING"
     * @param iv             The Initialization Vector bytes
     * @return The modified data
     */
    private static byte[] modify(int mode, byte[] data, Key key, String transformation, byte[] iv) {
        byte[] modifiedData = null;

        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(mode, key, new IvParameterSpec(iv));
            modifiedData = cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } finally {
            return modifiedData;
        }
    }

}
