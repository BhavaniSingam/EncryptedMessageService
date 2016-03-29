package encryption;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/**
 * Contains functionality to accepts a connections from the client
 *
 * @author Brian Mc George
 */
public class ClientSession extends Session {
    private Socket socket;
    private BufferedReader inputReader;
    private PrintWriter printWriter;

    public ClientSession() throws IOException {
        this("127.0.0.1");
    }

    public ClientSession (String destination) throws IOException {
        this(destination, PORT);
    }

    public ClientSession(String destination, int port) throws IOException {
        socket = new Socket();
        socket.connect(new InetSocketAddress(destination, port));
        printWriter = new PrintWriter(socket.getOutputStream(),true);
        InputStreamReader inputstreamreader = new InputStreamReader(socket.getInputStream());
        inputReader = new BufferedReader(inputstreamreader);
        System.out.println("Connected to " + destination + ":" +port);
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
}
