package encryption;


import java.io.IOException;

import static java.lang.Thread.sleep;

public class ClientMain {
    public static void main(String[] args) {
        try {
            ClientSession clientSession = new ClientSession();
            while(true) {
                String message = clientSession.captureUserInput();
                clientSession.sendMessage(message);
                // General test for byte array:
                clientSession.sendMessage("TestStringToBytes".getBytes());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
