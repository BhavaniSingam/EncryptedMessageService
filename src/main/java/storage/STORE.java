package storage;


import java.io.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * <h1>STORE</h1>
 * A class that contains functions to store and retrieve RSA public and private keys
 * @author Michael Kyeyune
 * @since 2016-03-31
 */
public class STORE
{
    /**
     * A method to save the provided public key to the provided file.
     * @param fileName The name of the file to save the key to.
     * @param publicKey The public key to save to file.
     */
    public static void savePublicKeyToFile(String fileName, PublicKey publicKey)
    {
        try
        {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
            saveToFile(fileName, publicKeySpec.getModulus(), publicKeySpec.getPublicExponent());
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        catch (InvalidKeySpecException e)
        {
            e.printStackTrace();
        }
    }

    /**
     * A method to save the provided private key to the provided file.
     * @param fileName The name of the file to save the key to.
     * @param privateKey The private key to save to file.
     */
    public static void savePrivateKeyToFile(String fileName, PrivateKey privateKey)
    {
        try
        {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
            saveToFile(fileName, privateKeySpec.getModulus(), privateKeySpec.getPrivateExponent());
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    /**
     * A method to read a public key from a given file
     * @param fileName The name of the file in which the public key is stored
     * @return PublicKey The public key retrieved from file.
     */
    public static PublicKey readPublicKeyFromFile(String fileName)
    {
        PublicKey publicKey = null;
        try
        {
            InputStream inputStream = new FileInputStream(fileName);
            ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(inputStream));

            BigInteger m = (BigInteger) objectInputStream.readObject();
            BigInteger e = (BigInteger) objectInputStream.readObject();

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m,e);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);

        }
        catch (FileNotFoundException e)
        {
            e.printStackTrace();
        }
        catch (IOException e)
        {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        finally {
            return publicKey;
        }

    }

    /**
     * A method to read a private key from a file.
     * @param fileName The file to read the private key from.
     * @return PrivateKey The private key read from file.
     */
    public static PrivateKey readPrivateKeyFromFile(String fileName)
    {
        PrivateKey privateKey = null;

        try
        {
            InputStream inputStream = new FileInputStream(fileName);
            ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(inputStream));

            BigInteger m = (BigInteger) objectInputStream.readObject();
            BigInteger e = (BigInteger) objectInputStream.readObject();

            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m,e);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        }
        catch (FileNotFoundException e)
        {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        finally {
            return privateKey;
        }

    }

    /*
     * A method to write the key mod and exp to the specified file.
     * @param fileName The name of the file to write to.
     * @param mod The mod of the key.
     * @param exp The exponent of the key.
     */
    private static void saveToFile(String fileName, BigInteger mod, BigInteger exp)
    {
        try {
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
            objectOutputStream.writeObject(mod);
            objectOutputStream.writeObject(exp);
            objectOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
