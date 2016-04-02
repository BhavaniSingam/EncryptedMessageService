package storage;


import java.io.*;
import java.math.BigInteger;
import java.security.*;
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
     * A method that generates the key ID using the public key
     * @param publicKey The public key
     * @return 64 bit key ID
     */
    public static long generateKeyID(PublicKey publicKey)
    {
        //TODO: utilise BigInteger & with (18446744073709551615) which is (2^64)-1
        long keyID = 0;

        try
        {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
            keyID = (publicKeySpec.getModulus()).longValue();
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return keyID;
    }

    /**
     * A method that writes the provided keys to the provided private key ring file
     * @param publicKey The public key
     * @param privateKey The private key
     * @param fileName The private key ring file name
     * @return long The key ID generated for this key pair in the key ring
     */
    public static long saveKeysToPrivateKeyRing(PublicKey publicKey, PrivateKey privateKey, String fileName)
    {
        long keyID = 0;

        try
        {
            FileWriter writer = new FileWriter(fileName);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
            RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);

            //convert key mods and exponents to string
            String publicMod = (publicKeySpec.getModulus()).toString();
            String publicExp = (publicKeySpec.getPublicExponent()).toString();

            String privateMod = (privateKeySpec.getModulus()).toString();
            String privateExp = (privateKeySpec.getPrivateExponent()).toString();

            //generate key for the key pair to be used in key ring
            keyID = generateKeyID(publicKey);

            //write content to key ring file
            writer.append(keyID + "");
            writer.append(",");

            writer.append(publicMod);
            writer.append(",");
            writer.append(publicExp);
            writer.append(",");

            writer.append(privateMod);
            writer.append(",");
            writer.append(privateExp);
            writer.append("\n");

            writer.flush();
            writer.close();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return keyID;
    }

    /**
     * A method that writes the public key to the specified public key ring
     * @param keyID The ID of the key
     * @param publicKey The public key
     * @param fileName The public key ring file name
     */
    public static void saveKeyToPublicKeyRing(long keyID, PublicKey publicKey, String fileName)
    {
        try
        {
            FileWriter writer = new FileWriter(fileName);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);

            //convert key mods and exponents to string
            String publicMod = (publicKeySpec.getModulus()).toString();
            String publicExp = (publicKeySpec.getPublicExponent()).toString();

            //write content to key ring file
            writer.append(keyID + "");
            writer.append(',');
            writer.append(publicMod);
            writer.append(',');
            writer.append(publicExp);
            writer.append("\n");

            writer.flush();
            writer.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    /**
     * A method to read a public key from the public key ring
     * @param keyID The ID of the key in the key ring
     * @param fileName
     * @return PublicKey The public key retrieved from the key ring
     */
    public static PublicKey readKeyFromPublicKeyRing(long keyID, String fileName)
    {
        PublicKey publicKey = null;

        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName));

            //iterate through key ring looking for row with specified key ID
            String line;
            while((line = bufferedReader.readLine()) != null)
            {
                String[] keyRingRow = line.split(",");

                String retrievedKeyID = keyRingRow[0];
                String retrievedPublicMod = keyRingRow[1];
                String retrievedPublicExp = keyRingRow[2];

                //assumes that key IDs are unique in key ring
                if(retrievedKeyID.equals(keyID + ""))
                {
                    BigInteger mod = new BigInteger(retrievedPublicMod);
                    BigInteger exp = new BigInteger(retrievedPublicExp);

                    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(mod, exp);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    publicKey = keyFactory.generatePublic(publicKeySpec);
                }
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return publicKey;
    }

    public static KeyPair readKeysFromPrivateKeyRing(long keyID, String fileName)
    {
        KeyPair keyPair = null;

        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName));

            //iterate through key ring looking for row with specified key ID
            String line;
            while((line = bufferedReader.readLine()) != null)
            {
                String[] keyRingRow = line.split(",");

                String retrievedKeyID = keyRingRow[0];

                //assumes that key IDs are unique in key ring
                if(retrievedKeyID.equals(keyID + ""))
                {
                    String retrievedPublicMod = keyRingRow[1];
                    String retrievedPublicExp = keyRingRow[2];

                    String retrievedPrivateMod = keyRingRow[3];
                    String retrievedPrivateExp = keyRingRow[4];

                    BigInteger publicMod = new BigInteger(retrievedPublicMod);
                    BigInteger publicExp = new BigInteger(retrievedPublicExp);

                    BigInteger privateMod = new BigInteger(retrievedPrivateMod);
                    BigInteger privateExp = new BigInteger(retrievedPrivateExp);

                    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(publicMod, publicExp);
                    RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(privateMod, privateExp);

                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
                    PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

                    keyPair = new KeyPair(publicKey, privateKey);
                }
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return keyPair;
    }

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
