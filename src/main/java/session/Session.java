package session;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
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
    protected static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    protected static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    protected static final String SIGNATURE_TRANSFORMATION = "SHA1WithRSA";
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
        String sendMessage = Base64.getEncoder().encodeToString(message);
        sendMessage(printWriter, sendMessage);
    }

    /**
     * Send a message using a provided printWriter
     * @param printWriter
     * @param message a Base64 encoded String
     */
    public void sendMessage(PrintWriter printWriter, String message) {
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

    public RSAPublicKey retrieveRSAPublicKey(Socket socket) throws IOException, ClassNotFoundException {
        ObjectInputStream objInS = new ObjectInputStream(socket.getInputStream());
        RSAPublicKey key = (RSAPublicKey) objInS.readObject();
        return key;
    }

    public void sendRSAPublicKey(RSAPublicKey publicKey, Socket socket) throws IOException {
        ObjectOutputStream objOutS = new ObjectOutputStream(socket.getOutputStream());
        objOutS.writeObject(publicKey);
        objOutS.flush();
    }


}
