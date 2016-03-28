package encryption;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Contains functionality to accepts a connections from the client
 *
 * @author Brian Mc George
 */
public class ServerSession extends Session {
    private ServerSocket serversocket;
    private Socket socket;
    private BufferedReader inputReader;

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

    public byte[][] fetchMessages() throws IOException {
        String input;
        List<byte[]> messages = new ArrayList<>();

        while (inputReader.ready() && (input = inputReader.readLine()) != null) {
            messages.add(input.getBytes(StandardCharsets.UTF_8));
            System.out.println("Received encrypted message encoded as UTF-8: " + input);
            System.out.println("Received Byte array: " + input.getBytes(StandardCharsets.UTF_8));
        }

        byte[][] messageByteArray = new byte[messages.size()][];
        for(int i = 0; i < messageByteArray.length; ++i) {
            messageByteArray[i] = messages.get(i);
        }

        return messageByteArray;
    }

    /**
     * Wait indefinitely until a client connects to the socket
     * @throws IOException
     */
    public void waitForConnection() throws IOException {
        System.out.println("Listening at 127.0.0.1 on port " + serversocket.getLocalPort());
        socket = serversocket.accept();
        InputStreamReader inputstreamreader = new InputStreamReader(socket.getInputStream());
        inputReader = new BufferedReader(inputstreamreader);
        System.out.println("Connected to ClientSession.");
    }
}
