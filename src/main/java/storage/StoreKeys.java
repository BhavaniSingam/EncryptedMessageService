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

    public static void main(String[] args)
    {
        KeyPair clientKeyPair = RSA.generateKeyPair(2048);
        KeyPair serverKeyPair = RSA.generateKeyPair(2048);

        //save both client and server public keys in their key collections
        STORE.savePublicKeyToFile(CLIENT_KEYS_FOLDER + "client-public.store", clientKeyPair.getPublic());
        STORE.savePublicKeyToFile(SERVER_KEYS_FOLDER + "client-public.store", clientKeyPair.getPublic());

        STORE.savePublicKeyToFile(SERVER_KEYS_FOLDER + "server-public.store", serverKeyPair.getPublic());
        STORE.savePublicKeyToFile(CLIENT_KEYS_FOLDER + "server-public.store", serverKeyPair.getPublic());

        //save the private keys in only the expected key collections
        STORE.savePrivateKeyToFile(CLIENT_KEYS_FOLDER + "client-private.store", clientKeyPair.getPrivate());
        STORE.savePrivateKeyToFile(SERVER_KEYS_FOLDER + "server-private.store", serverKeyPair.getPrivate());
    }
}
