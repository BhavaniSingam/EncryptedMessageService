package session;

import encryption.AES;
import encryption.RSA;
import signature.DigitalSignature;
import storage.STORE;
import zipping.ZIP;

import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static java.lang.Thread.sleep;

/**
 * Contains functionality required for a regular session
 *
 * @author Brian Mc George
 */
class Session {
    protected static final int PORT = 8888;
    protected static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    protected static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    protected static final String SIGNATURE_TRANSFORMATION = "SHA1WithRSA";
    protected static final int SLEEP_TIME = 500;
    private RSAPrivateKey localPrivateKey;
    private RSAPublicKey localPublicKey;
    private RSAPublicKey remotePublicKey;
    private Key AESKey;

    // ===================================================== Message Sending =========================================================

    /**
     * Encrypts a message and then sends it
     *
     * @param IVSecureRandom an SecureRandom object
     * @param printWriter    to facilitate sending the message
     * @param message        a byte array
     * @throws IOException
     */
    public void sendMessage(SecureRandom IVSecureRandom,
                            PrintWriter printWriter, Set<String> usedNonces, byte[] message) throws IOException {
        byte[] output = encryptMessage(IVSecureRandom, usedNonces, message);
        sendMessage(printWriter, output);
    }

    /**
     * Send an encrypted message using a provided printWriter
     *
     * @param printWriter to facilitate sending the message
     * @param message     a byte array
     */
    public void sendMessage(PrintWriter printWriter, byte[] message) {
        String sendMessage = Base64.getEncoder().encodeToString(message);
        sendMessage(printWriter, sendMessage);
    }

    /**
     * Send a message using a provided printWriter
     *
     * @param printWriter to facilitate sending the message
     * @param message     a Base64 encoded String
     */
    private void sendMessage(PrintWriter printWriter, String message) {
        printWriter.println(message);
        System.out.println("Send message (Base64): " + message);
    }

    // ===================================================== Message Retrieval =========================================================

    public byte[] fetchMessage(BufferedReader inputReader) throws IOException {
        String input;
        byte[] decodedInput = null;

        if (inputReader.ready() && (input = inputReader.readLine()) != null) {
            decodedInput = Base64.getDecoder().decode(input);
        }

        return decodedInput;
    }

    public byte[][] fetchMessages(Set<String> usedNonces, BufferedReader inputReader)
            throws IOException {
        String input;
        List<byte[]> messages = new ArrayList<>();
        while (inputReader.ready() && (input = inputReader.readLine()) != null) {
            byte[] decodedInput = decryptMessage(input, usedNonces);
            messages.add(decodedInput);
        }

        byte[][] messageByteArray = new byte[messages.size()][];
        for (int i = 0; i < messageByteArray.length; ++i) {
            messageByteArray[i] = messages.get(i);
        }

        return messageByteArray;
    }

    public byte[] pollForMessage(BufferedReader inputReader) throws IOException, InterruptedException {
        byte[] message = null;
        do {
            message = fetchMessage(inputReader);
            if (message == null) {
                sleep(SLEEP_TIME);
            }
        } while (message == null);

        return message;
    }

    // ===================================================== Message Encryption =========================================================

    public byte[] encryptHandshakeMessage(long receiverRSAKey, long senderRSAKey, SecureRandom IVSecureRandom, Set<String> usedNonces) throws IOException {
        System.out.println("Encrypt handshake message");

        // Send the RSAKeyID of receiver
        ByteBuffer byteBuffer = ByteBuffer.allocate(Long.BYTES);
        byteBuffer.putLong(0, receiverRSAKey);
        byte[] receiverKeyID = byteBuffer.array();
        System.out.println("Receiver RSA key id: " + receiverRSAKey);

        int AESKeyBits = AESKey.getEncoded().length * 8;
        System.out.println("Generated an AES key of " + AESKey.getEncoded().length * 8 + " bits");
        System.out.println("AES key (visualised as a base64 string): " + Base64.getEncoder().encodeToString(AESKey.getEncoded()));

        // Encrypt the AES key
        byte[] encryptedKey = RSA.encrypt(AESKey.getEncoded(), remotePublicKey, RSA_TRANSFORMATION);
        System.out.println("Encrypted AES key with server public key, length of encrypted key is " + encryptedKey.length * 8 + " bits");
        System.out.println("Encrypted AES key (Base64): " + Base64.getEncoder().encodeToString(encryptedKey));

        // Generate nonce / random salt - this can be sent as plaintext
        byte[] nonce = generateNonce(IVSecureRandom, usedNonces, AESKeyBits);

        // ========== Hello Message ==========
        String text = "PGP Hello";
        byte[] clientMessage = text.getBytes("UTF8");
        System.out.println("Sending an initial hello message: " + text);

        // ========== encryptedMessage ==========
        byte[] encryptedMessage = constructEncryptedMessage(clientMessage, nonce, senderRSAKey);

        // ========== Final message construction ==========
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(receiverKeyID);
        outputStream.write(encryptedKey);
        outputStream.write(nonce);
        outputStream.write(encryptedMessage);
        byte[] output = outputStream.toByteArray();

        return output;
    }

    public byte[] encryptMessage(SecureRandom IVSecureRandom,
                                 Set<String> usedNonces, byte[] message) throws IOException {
        System.out.println("Encrypt message");

        int AESKeyBits = AESKey.getEncoded().length * 8;
        byte[] nonce = generateNonce(IVSecureRandom, usedNonces, AESKeyBits);

        // ========== encryptedMessage ==========
        byte[] encryptedMessage = constructEncryptedMessage(message, nonce);

        // ========== Final message construction ==========
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(nonce);
        outputStream.write(encryptedMessage);
        byte[] output = outputStream.toByteArray();

        return output;
    }

    private byte[] generateNonce(SecureRandom IVSecureRandom, Set<String> usedNonces, int keyBits) {
        // Generate a nonce
        byte[] nonce;
        String nonceTxt;
        do {
            nonce = AES.generateIV(IVSecureRandom, keyBits);
            nonceTxt = Base64.getEncoder().encodeToString(nonce);
        } while (usedNonces.contains(nonceTxt));
        usedNonces.add(nonceTxt);
        System.out.println("Nonce generated (visualised as base64): " + nonceTxt);
        return nonce;
    }

    private byte[] constructEncryptedMessage(byte[] message, byte[] nonce) throws IOException {
        return constructEncryptedMessage(message, nonce, null);
    }

    private byte[] constructEncryptedMessage(byte[] message, byte[] nonce, Long senderRSAKey) throws IOException {
        // ========== Message contents ==========
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(message);
        byte[] messageContents = outputStream.toByteArray();
        System.out.println("Message contents (Base64): " + Base64.getEncoder().encodeToString(messageContents));

        // ========== Signature ==========
        byte[] signature = DigitalSignature.generateSignature(messageContents, localPrivateKey, SIGNATURE_TRANSFORMATION);
        System.out.println("Signature has " + signature.length + " bits");
        System.out.println("Signature (visualised as base64 String): " + Base64.getEncoder().encodeToString(signature));

        // ========== Concatenate signature and message ==========
        outputStream.reset();

        // RSA Key id (if available)
        // We only send this for the handshake
        if (senderRSAKey != null) {
            // Send the RSAKeyID of receiver
            ByteBuffer byteBuffer = ByteBuffer.allocate(Long.BYTES);
            byteBuffer.putLong(0, senderRSAKey);
            byte[] senderKeyID = byteBuffer.array();
            outputStream.write(senderKeyID);
            System.out.println("Sender RSA key ID: " + senderRSAKey);
        }

        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.putInt(signature.length);
        outputStream.write(byteBuffer.array());
        outputStream.write(signature);

        outputStream.write(messageContents);

        byte[] concatenatedSignatureAndMessage = outputStream.toByteArray();
        System.out.println("Concatenated signature and message (Base64): " + Base64.getEncoder().encodeToString(concatenatedSignatureAndMessage));
        System.out.println("Before zipping length: " + concatenatedSignatureAndMessage.length);
        byte[] zippedMessage = ZIP.compress(concatenatedSignatureAndMessage);
        System.out.println("After zipping length: " + zippedMessage.length);

        System.out.println("Zipped message (Base64): " + Base64.getEncoder().encodeToString(zippedMessage));
        byte[] encryptedMessage = AES.encrypt(zippedMessage, AESKey, AES_TRANSFORMATION, nonce);
        System.out.println("Encrypted message (Base64): " + Base64.getEncoder().encodeToString(encryptedMessage));

        return encryptedMessage;
    }

    // ===================================================== Message Decryption =========================================================

    public String decryptHandshakeMessage(byte[] receivedMessage, String receiverKeyFolder, String privateKeyRingFileName, String publicKeyRingFileName,
                                          Set<String> usedNonces) throws UnsupportedEncodingException {
        System.out.println("Decrypt handshake message");
        System.out.println("Received encrypted message (Base64): " + Base64.getEncoder().encodeToString(receivedMessage));

        // ========== Receiver RSA key ID ==========
        ByteBuffer byteArray = ByteBuffer.allocate(Long.BYTES);
        byteArray.put(receivedMessage, 0, Long.BYTES);
        byteArray.flip();
        long receiverRSAKeyID = byteArray.getLong();
        System.out.println("Receiver RSA key ID: " + receiverRSAKeyID);

        // Read 2048 bit RSA keys from file
        KeyPair readKeyPair = STORE.readKeysFromPrivateKeyRing(receiverRSAKeyID, receiverKeyFolder + privateKeyRingFileName);
        localPublicKey = (RSAPublicKey) readKeyPair.getPublic();
        localPrivateKey = (RSAPrivateKey) readKeyPair.getPrivate();

        // ========== Fetch the message from the client ==========
        int encryptedAESKeyLength = localPublicKey.getModulus().bitLength() / 8;
        byte[] encryptedKey = Arrays.copyOfRange(receivedMessage, Long.BYTES, Long.BYTES + encryptedAESKeyLength);
        byte[] AESKeyByteArray = RSA.decrypt(encryptedKey, localPrivateKey, RSA_TRANSFORMATION);
        System.out.println("Encrypted AES key (Base64): " + Base64.getEncoder().encodeToString(encryptedKey));
        System.out.println("AES key (Base64): " + Base64.getEncoder().encodeToString(AESKeyByteArray));
        AESKey = new SecretKeySpec(AESKeyByteArray, 0, AESKeyByteArray.length, "AES");

        // ========== Random Salt ==========
        int IVStartIndex = Long.BYTES + encryptedAESKeyLength;
        byte[] nonce = getNonce(IVStartIndex, IVStartIndex + AESKeyByteArray.length, receivedMessage, usedNonces);
        if (nonce == null) {
            return null;
        }

        // ========== Decrypt message ==========
        int encryptedDataStartIndex = IVStartIndex + AESKeyByteArray.length;
        byte[] unzippedData = decryptMessage(encryptedDataStartIndex, receivedMessage.length, receivedMessage, nonce);

        // ========== Sender public key ID ==========
        ByteBuffer senderPublicKeyID = ByteBuffer.allocate(Long.BYTES);
        senderPublicKeyID.put(unzippedData, 0, Long.BYTES);
        senderPublicKeyID.flip();
        long senderRSAKeyID = senderPublicKeyID.getLong();
        remotePublicKey = (RSAPublicKey) STORE.readKeyFromPublicKeyRing(senderRSAKeyID, receiverKeyFolder + publicKeyRingFileName);
        System.out.println("Sender RSA key ID: " + senderRSAKeyID);

        // ========== Get verified message =========
        byte[] messageSection = getVerifiedMessage(Long.BYTES, unzippedData);
        if (messageSection == null) {
            return null;
        }

        // Now that the message is valid we add it to the used nonces set
        usedNonces.add(Base64.getEncoder().encodeToString(nonce));

        // ========== Message ==========
        byte[] messageContents = Arrays.copyOfRange(messageSection, 0, messageSection.length);

        return new String(messageContents, "UTF8");
    }

    public byte[] decryptMessage(String input, Set<String> usedNonces) throws
            UnsupportedEncodingException {
        System.out.println("Decrypt message");
        System.out.println("Received encrypted message (Base64): " + input);

        byte[] receivedMessage = Base64.getDecoder().decode(input);

        int AESKeyLength = AESKey.getEncoded().length;

        // ========== Random Salt ==========
        byte[] nonce = getNonce(0, AESKeyLength, receivedMessage, usedNonces);
        if (nonce == null) {
            return null;
        }

        // ========== Decrypt message ==========
        int encryptedDataStartIndex = AESKeyLength;
        byte[] unzippedData = decryptMessage(encryptedDataStartIndex, receivedMessage.length, receivedMessage, nonce);

        // ========== Get verified message =========
        byte[] messageSection = getVerifiedMessage(0, unzippedData);
        if (messageSection == null) {
            return null;
        }
        usedNonces.add(Base64.getEncoder().encodeToString(nonce));

        // ========== Message ==========
        byte[] messageContents = Arrays.copyOfRange(messageSection, 0, messageSection.length);
        System.out.println("Message: " + new String(messageContents, "UTF8"));
        System.out.println();

        return messageContents;
    }

    public byte[] getNonce(int IVStartIndex, int IVEndIndex, byte[] receivedMessage, Set<String> usedNonces) {
        byte[] nonce = Arrays.copyOfRange(receivedMessage, IVStartIndex, IVEndIndex);
        String nonceTxt = Base64.getEncoder().encodeToString(nonce);
        if (usedNonces.contains(nonceTxt)) {
            System.out.println("Nonce has already been used, dropping message");
            return null;
        }
        System.out.println("Nonce (Base64): " + Base64.getEncoder().encodeToString(nonce));
        return nonce;
    }

    private byte[] decryptMessage(int startIndex, int endIndex, byte[] receivedMessage, byte[] nonce) {
        byte[] encryptedData = Arrays.copyOfRange(receivedMessage, startIndex, endIndex);
        System.out.println("Encrypted data (Base64): " + Base64.getEncoder().encodeToString(encryptedData));

        // ========== Decrypt message ==========
        byte[] unencryptedData = AES.decrypt(encryptedData, AESKey, AES_TRANSFORMATION, nonce);
        System.out.println("Zipped Data (Base64): " + Base64.getEncoder().encodeToString(unencryptedData));
        byte[] unzippedData = ZIP.decompress(unencryptedData);
        System.out.println("Concatenated signature and message (Base64): " + Base64.getEncoder().encodeToString(unzippedData));

        return unzippedData;
    }

    private byte[] getVerifiedMessage(int startIndex, byte[] unzippedData) {
        // ========== Signature length ==========
        ByteBuffer byteBuffer = ByteBuffer.wrap(Arrays.copyOfRange(unzippedData, startIndex, startIndex + 4));
        int signatureLength = byteBuffer.getInt();
        System.out.println("Signature length: " + signatureLength);

        // ========== Signature and verification ==========
        byte[] signature = Arrays.copyOfRange(unzippedData, startIndex + 4, startIndex + 4 + signatureLength);
        System.out.println("Signature (Base64): " + Base64.getEncoder().encodeToString(signature));


        byte[] messageSection = Arrays.copyOfRange(unzippedData, startIndex + 4 + signatureLength, unzippedData.length);
        if (!DigitalSignature.verifySignature(messageSection, signature, remotePublicKey, SIGNATURE_TRANSFORMATION)) {
            System.out.println("Signature does not match, ignoring message");
            return null;
        }

        return messageSection;
    }

    public void setLocalPublicKey(RSAPublicKey publicKey) {
        localPublicKey = publicKey;
    }

    public void setLocalPrivateKey(RSAPrivateKey privateKey) {
        localPrivateKey = privateKey;
    }

    public void setRemotePublicKey(RSAPublicKey publicKey) {
        remotePublicKey = publicKey;
    }

    public void setAESKey(Key key) {
        AESKey = key;
    }
}
