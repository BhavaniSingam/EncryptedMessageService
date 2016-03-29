package encryption;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static java.lang.Thread.sleep;

/**
 * Contains functionality required for a regular session
 */
class Session {
    protected static final int PORT = 8888;
    protected static final String AES_TRANSFORMATION = "AES/CBC/PKCS7PADDING";
    protected static final int SLEEP_TIME = 500;
    private BufferedReader systemInputReader;

    Session() {
        systemInputReader = new BufferedReader(new InputStreamReader(System.in));
    }

    /**
     * Send a message using a provided printWriter
     * @param printWriter
     * @param message a byte array
     */
    public void sendMessage(PrintWriter printWriter, byte[] message) {
        sendMessage(printWriter, Base64.getEncoder().encodeToString(message));
        System.out.println("Send: " + message + " encoded as Base 64");
    }

    /**
     * Send a message using a provided printWriter
     * @param printWriter
     * @param message a Base64 encoded String
     */
    public void sendMessage(PrintWriter printWriter, String message) {
        printWriter.println(message);
        System.out.println("Send message: " + message);
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

    public byte[][] fetchMessages(BufferedReader inputReader) throws IOException {
        String input;
        List<byte[]> messages = new ArrayList<>();

        while (inputReader.ready() && (input = inputReader.readLine()) != null) {
            byte[] decodedInput = Base64.getDecoder().decode(input);
            messages.add(decodedInput);
            System.out.println("Received encrypted message encoded as Base64: " + input);
            System.out.println("Received Byte array: " + decodedInput);
        }

        byte[][] messageByteArray = new byte[messages.size()][];
        for(int i = 0; i < messageByteArray.length; ++i) {
            messageByteArray[i] = messages.get(i);
        }

        return messageByteArray;
    }

    public byte[] pollForMessage(BufferedReader inputReader) throws IOException, InterruptedException {
        byte[] message = null;
        do {
            message = fetchMessage(inputReader);
            if(message == null) {
                sleep(SLEEP_TIME);
            }
        } while(message == null);

        return message;
    }

    public BigInteger generateNonce(SecureRandom secureRandom, Set<BigInteger> usedNonces) {
        BigInteger nonce;
        do {
            nonce = new BigInteger(64, secureRandom);
        } while(usedNonces.contains(nonce));
        usedNonces.add(nonce);
        return nonce;
    }


}
