package storage;

import encryption.RSA;

import java.security.KeyPair;

/**
 * <h1>StoreKeys</h1>
 * A class that writes the public and private keys to the resources folder
 * @author Michael Kyeyune
 * @since 2016-01-04
 */
public class StoreKeys
{
    public static final String CLIENT_KEYS_FOLDER = "src/main/resources/keys/client/";
    public static final String SERVER_KEYS_FOLDER = "src/main/resources/keys/server/";

    public static final String PUBLIC_KEY_RING_FILE_NAME = "public-key-ring.csv";
    public static final String PRIVATE_KEY_RING_FILE_NAME = "private-key-ring.csv";

    public static long SERVER_KEYID = 7319054409054031671L;
    public static long CLIENT_KEYID = 4595080166660471803L;

    public static void main(String[] args)
    {
        KeyPair clientKeyPair = RSA.generateKeyPair(2048);
        KeyPair serverKeyPair = RSA.generateKeyPair(2048);

        //save to respective private key rings
        long clientKeyID = STORE.saveKeysToPrivateKeyRing(clientKeyPair.getPublic(), clientKeyPair.getPrivate(), CLIENT_KEYS_FOLDER + PRIVATE_KEY_RING_FILE_NAME);
        long serverKeyID = STORE.saveKeysToPrivateKeyRing(serverKeyPair.getPublic(), serverKeyPair.getPrivate(), SERVER_KEYS_FOLDER + PRIVATE_KEY_RING_FILE_NAME);

        //save the public keys in the opposite entity's public key ring
        STORE.saveKeyToPublicKeyRing(serverKeyID, serverKeyPair.getPublic(), CLIENT_KEYS_FOLDER + PUBLIC_KEY_RING_FILE_NAME);
        STORE.saveKeyToPublicKeyRing(clientKeyID, clientKeyPair.getPublic(), SERVER_KEYS_FOLDER + PUBLIC_KEY_RING_FILE_NAME);
    }
}
