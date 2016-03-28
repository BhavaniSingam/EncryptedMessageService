package encryption;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Contains functionality required for a regular session
 */
class Session {
    protected static final int PORT = 8888;
    private BufferedReader systemInputReader;

    Session() {
        systemInputReader = new BufferedReader(new InputStreamReader(System.in));
    }

    public void sendMessage(PrintWriter printWriter, byte[] message) throws UnsupportedEncodingException {
        sendMessage(printWriter, new String(message, StandardCharsets.UTF_8));
        System.out.println("Send: " + message + " encoded as UTF-8");
    }

    public void sendMessage(PrintWriter printWriter, String message) throws UnsupportedEncodingException {
        printWriter.println(message);
        System.out.println("Send message: " + message);
    }

    public String captureUserInput() throws IOException {
       return systemInputReader.readLine();
    }
}
