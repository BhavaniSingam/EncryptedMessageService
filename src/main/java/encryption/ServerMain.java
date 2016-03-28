package encryption;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static java.lang.Thread.sleep;

public class ServerMain {
    public static void main(String[] args) {
        try {
            ServerSession serverSession = new ServerSession();
            serverSession.waitForConnection();
            while(true) {
                byte[][] messages = serverSession.fetchMessages();
                for(byte[] message : messages) {
                    System.out.println(new String(message, StandardCharsets.UTF_8));
                }
                sleep(500);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }


}
