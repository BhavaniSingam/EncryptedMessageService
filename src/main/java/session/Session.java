package session;

import encryption.AES;
import signature.DigitalSignature;
import zipping.ZIP;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.Key;
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
    private BufferedReader systemInputReader;

    Session() {
        systemInputReader = new BufferedReader(new InputStreamReader(System.in));
    }

    /**
     * Encrypts a message and then sends it
     *
     * @param AES_KEY_LENGTH number of bits in the AES key
     * @param IVSecureRandom an SecureRandom object
     * @param privateKey     private key of the sender
     * @param AESKey         the AES key that has already been shared between the sender and receiver
     * @param printWriter    to facilitate sending the message
     * @param message        a byte array
     * @throws IOException
     */
    public void sendMessage(final int AES_KEY_LENGTH, SecureRandom IVSecureRandom, SecureRandom saltSecureRandom, RSAPrivateKey privateKey, Key AESKey,
                            PrintWriter printWriter, Set<String> usedNonces, byte[] message) throws IOException {
        byte[] output = encryptMessage(AES_KEY_LENGTH, IVSecureRandom, saltSecureRandom, privateKey, AESKey, usedNonces, message);
        sendMessage(printWriter, output);
    }

    public byte[] encryptMessage(final int AES_KEY_LENGTH, SecureRandom IVSecureRandom, SecureRandom saltSecureRandom, RSAPrivateKey privateKey, Key AESKey,
                                 Set<String> usedNonces, byte[] message) throws IOException {
        // Generate random salt - this can be sent as plaintext
        byte[] iv = AES.generateIV(saltSecureRandom, AES_KEY_LENGTH);
        System.out.println("Random salt generated (visualised as a base64 string): " + Base64.getEncoder().encodeToString(iv));

        // Generate a nonce
        byte[] nonce;
        String nonceTxt;
        do {
            nonce = AES.generateIV(IVSecureRandom, 64);
            nonceTxt = Base64.getEncoder().encodeToString(nonce);
        } while (usedNonces.contains(nonceTxt));
        usedNonces.add(nonceTxt);
        System.out.println("64 bit nonce generated (visualised as base64): " + nonceTxt);

        // ========== Message contents ==========
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(nonce);
        outputStream.write(message);
        byte[] messageContents = outputStream.toByteArray();
        System.out.println("Message contents (Nonce and message), visualised as base64 string: " + Base64.getEncoder().encodeToString(messageContents));

        // ========== Signature ==========
        byte[] signature = DigitalSignature.generateSignature(messageContents, privateKey, SIGNATURE_TRANSFORMATION);
        System.out.println("Signature has " + signature.length + " bits");
        System.out.println("Signature (visualised as base64 String): " + Base64.getEncoder().encodeToString(signature));

        // ========== Concatenate signature and message ==========
        outputStream.reset();
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

        byte[] encryptedMessage = AES.encrypt(zippedMessage, AESKey, AES_TRANSFORMATION, iv);
        System.out.println("Encrypted message (Base64): " + Base64.getEncoder().encodeToString(encryptedMessage));

        // ========== Final message construction ==========
        outputStream.reset();

        // Include the length of the salt
        byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.putInt(iv.length);

        outputStream.write(byteBuffer.array());
        outputStream.write(iv);
        outputStream.write(encryptedMessage);
        byte[] output = outputStream.toByteArray();

        return output;
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

    public String captureUserInput() throws IOException {
        return systemInputReader.readLine();
    }

    public byte[] fetchMessage(BufferedReader inputReader) throws IOException {
        String input;
        byte[] decodedInput = null;

        if (inputReader.ready() && (input = inputReader.readLine()) != null) {
            decodedInput = Base64.getDecoder().decode(input);
            System.out.println("Received encrypted message encoded as Base64: " + input);
            System.out.println("Received Byte array: " + decodedInput);
        }

        return decodedInput;
    }

    public byte[][] fetchMessages(int encryptedAESKeyLength, Key AESKey, RSAPublicKey senderPublicKey, Set<String> usedNonces, BufferedReader inputReader)
            throws IOException {
        String input;
        List<byte[]> messages = new ArrayList<>();

        while (inputReader.ready() && (input = inputReader.readLine()) != null) {
            byte[] decodedInput = decryptMessage(input, encryptedAESKeyLength, AESKey, senderPublicKey, usedNonces);
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

    public byte[] decryptMessage(String input, int encryptedAESKeyLength, Key AESKey, RSAPublicKey senderPublicKey, Set<String> usedNonces) throws
            UnsupportedEncodingException {
        byte[] receivedMessage = Base64.getDecoder().decode(input);

        // ========== Salt length ==========
        ByteBuffer byteBuffer = ByteBuffer.wrap(Arrays.copyOfRange(receivedMessage, 0, 4));
        int ivNumberOfBytes = byteBuffer.getInt();
        System.out.println("Number of bits in the random salt (IV): " + ivNumberOfBytes * 8);

        // ========== Random Salt ==========
        int IVStartIndex = encryptedAESKeyLength + 4;
        byte[] iv = Arrays.copyOfRange(receivedMessage, 4, 4 + ivNumberOfBytes);
        System.out.println("Random salt (Base64): " + Base64.getEncoder().encodeToString(iv));

        // ========== Encrypted data ==========
        int encryptedDataStartIndex = 4 + ivNumberOfBytes;
        byte[] encryptedData = Arrays.copyOfRange(receivedMessage, encryptedDataStartIndex, receivedMessage.length);
        System.out.println("Encrypted data (Base64): " + Base64.getEncoder().encodeToString(encryptedData));

        // ========== Decrypt message ==========
        byte[] unencryptedData = AES.decrypt(encryptedData, AESKey, AES_TRANSFORMATION, iv);
        System.out.println("Unencrypted Data (Base64): " + Base64.getEncoder().encodeToString(unencryptedData));
        byte[] unzippedData = ZIP.decompress(unencryptedData);
        System.out.println("Unzipped Data (Base64): " + Base64.getEncoder().encodeToString(unzippedData));

        // ========== Signature length ==========
        byteBuffer = ByteBuffer.wrap(Arrays.copyOfRange(unzippedData, 0, 4));
        int signatureLength = byteBuffer.getInt();
        System.out.println("Signature length: " + signatureLength);

        // ========== Signature and verification ==========
        byte[] signature = Arrays.copyOfRange(unzippedData, 4, 4 + signatureLength);
        byte[] messageSection = Arrays.copyOfRange(unzippedData, 4 + signatureLength, unzippedData.length);
        if (!DigitalSignature.verifySignature(messageSection, signature, senderPublicKey, SIGNATURE_TRANSFORMATION)) {
            System.out.println("Signature does not match, ignoring message");
            return null;
        }

        // ========== Nonce ==========
        byte[] nonce = Arrays.copyOfRange(messageSection, 0, 8);
        String nonceTxt = Base64.getEncoder().encodeToString(nonce);
        System.out.println("Nonce (Base64): " + nonceTxt);
        if (usedNonces.contains(nonceTxt)) {
            System.out.println("Nonce has already been used, dropping message");
            return null;
        }
        usedNonces.add(nonceTxt);

        // ========== Message ==========
        byte[] messageContents = Arrays.copyOfRange(messageSection, 8, messageSection.length);
        System.out.println("Message: " + new String(messageContents, "UTF8"));

        return messageContents;
    }
}
