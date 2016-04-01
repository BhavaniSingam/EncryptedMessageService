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

    public static final String CLIENT_PUBLIC_KEY_FILE_NAME = "client-public.store";
    public static final String CLIENT_PRIVATE_KEY_FILE_NAME = "client-private.store";

    public static final String SERVER_PUBLIC_KEY_FILE_NAME = "server-public.store";
    public static final String SERVER_PRIVATE_KEY_FILE_NAME = "server-private.store";

    public static void main(String[] args)
    {
        KeyPair clientKeyPair = RSA.generateKeyPair(2048);
        KeyPair serverKeyPair = RSA.generateKeyPair(2048);

        //save both client and server public keys in their key collections
        STORE.savePublicKeyToFile(CLIENT_KEYS_FOLDER + CLIENT_PUBLIC_KEY_FILE_NAME, clientKeyPair.getPublic());
        STORE.savePublicKeyToFile(SERVER_KEYS_FOLDER + CLIENT_PUBLIC_KEY_FILE_NAME, clientKeyPair.getPublic());

        STORE.savePublicKeyToFile(SERVER_KEYS_FOLDER + SERVER_PUBLIC_KEY_FILE_NAME, serverKeyPair.getPublic());
        STORE.savePublicKeyToFile(CLIENT_KEYS_FOLDER + SERVER_PUBLIC_KEY_FILE_NAME, serverKeyPair.getPublic());

        //save the private keys in only the expected key collections
        STORE.savePrivateKeyToFile(CLIENT_KEYS_FOLDER + CLIENT_PRIVATE_KEY_FILE_NAME, clientKeyPair.getPrivate());
        STORE.savePrivateKeyToFile(SERVER_KEYS_FOLDER + SERVER_PRIVATE_KEY_FILE_NAME, serverKeyPair.getPrivate());
    }
}
