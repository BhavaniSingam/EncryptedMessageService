package session;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.interfaces.RSAPublicKey;

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
     * @throws IOException
     */
    public ServerSession () throws IOException {
        this(PORT);
    }

    /**
     * Constructs a default ServerSession with a specified port
     * @throws IOException
     */
    public ServerSession (int port) throws IOException {
        serversocket = new ServerSocket(port);
    }

    /**
     * Wait indefinitely until a client connects to the socket
     * @throws IOException
     */
    public void waitForConnection() throws IOException {
        System.out.println("Listening at 127.0.0.1 on port " + serversocket.getLocalPort());
        socket = serversocket.accept();
        printWriter = new PrintWriter(socket.getOutputStream(),true);
        InputStreamReader inputstreamreader = new InputStreamReader(socket.getInputStream());
        inputReader = new BufferedReader(inputstreamreader);
        System.out.println("Connected to ClientSession.");
    }

    /**
     * Sense a message using the socket created
     * @param message the byte array message to send
     *
     */
    public void sendMessage(byte[] message)  {
        sendMessage(printWriter, message);
    }

    public void sendMessage(String message) {
        sendMessage(printWriter, message);
    }

    public byte[] fetchMessage() throws IOException {
        return fetchMessage(inputReader);
    }

    public byte[][] fetchMessages() throws IOException {
        return fetchMessages(inputReader);
    }

    public byte[] pollForMessage() throws IOException, InterruptedException {
        return pollForMessage(inputReader);
    }

    public void sendRSAPublicKey(RSAPublicKey publicKey) throws IOException {
        sendRSAPublicKey(publicKey, socket);
    }

    public RSAPublicKey retrieveRSAPublicKey() throws IOException, ClassNotFoundException {
        return retrieveRSAPublicKey(socket);
    }
}
