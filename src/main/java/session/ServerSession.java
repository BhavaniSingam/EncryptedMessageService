package session;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;

/**
 * Contains functionality to accepts a connections from the client
 *
 * @author Brian Mc George
 */
public class ServerSession extends Session {
    private ServerSocket serversocket;
    private Socket socket;
    private BufferedReader inputReader;
    private PrintWriter printWriter;

    /**
     * Constructs a default ServerSession with the default port
     *
     * @throws IOException
     */
    public ServerSession() throws IOException {
        this(PORT);
    }

    /**
     * Constructs a default ServerSession with a specified port
     *
     * @throws IOException
     */
    public ServerSession(int port) throws IOException {
        serversocket = new ServerSocket(port);
    }

    /**
     * Wait indefinitely until a client connects to the socket
     *
     * @throws IOException
     */
    public void waitForConnection() throws IOException {
        System.out.println("Listening at 127.0.0.1 on port " + serversocket.getLocalPort());
        socket = serversocket.accept();
        printWriter = new PrintWriter(socket.getOutputStream(), true);
        InputStreamReader inputstreamreader = new InputStreamReader(socket.getInputStream());
        inputReader = new BufferedReader(inputstreamreader);
        System.out.println("Connected to ClientSession.");
    }

    public void sendMessage(SecureRandom IVSecureRandom, RSAPrivateKey privateKey, Key AESKey,
                            Set<String> usedNonces, byte[] message) throws IOException {
        sendMessage(IVSecureRandom, privateKey, AESKey, printWriter, usedNonces, message);
    }

    public byte[][] fetchMessages(Key AESKey, RSAPublicKey senderPublicKey, Set<String> usedNonces) throws IOException {
        return fetchMessages(AESKey, senderPublicKey, usedNonces, inputReader);
    }

    public byte[] pollForMessage() throws IOException, InterruptedException {
        return pollForMessage(inputReader);
    }
}
