package session;

import encryption.AES;
import encryption.RSA;
import signature.DigitalSignature;
import storage.STORE;
import storage.StoreKeys;
import zipping.ZIP;

import java.awt.*;
import java.awt.event.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import static session.Session.*;

/**
 * @author Brian Mc George
 */
public class ServerUI extends JFrame {
    private JFrame frame;
    private JTextArea receiveText;
    private JButton sendButton;
    //Heading
    private JLabel checkboxHeading;
    JButton listenButton;

    private JTextArea sendText;
    ServerSession serverSession;

    Key AESKey;

    SecureRandom IVSecureRandom = new SecureRandom();
    Set<String> usedNonces = new HashSet<>();

    // ========== RSA key exchange ==========
    // Read 2048 bit RSA keys from file
    KeyPair readKeyPair = STORE.readKeysFromPrivateKeyRing(5919969100937786679L, StoreKeys.SERVER_KEYS_FOLDER + StoreKeys.PRIVATE_KEY_RING_FILE_NAME);
    RSAPublicKey serverPublicKey = (RSAPublicKey) readKeyPair.getPublic();
    RSAPrivateKey serverPrivateKey = (RSAPrivateKey) readKeyPair.getPrivate();

    // Retrieve server public key
    RSAPublicKey clientPublicKey = (RSAPublicKey) STORE.readKeyFromPublicKeyRing(-7975117869850543847L, StoreKeys.SERVER_KEYS_FOLDER + StoreKeys.PUBLIC_KEY_RING_FILE_NAME);

    //Constructor
    public ServerUI() {
        initialize();
    }

    private void initialize() {
        try {
            // Set System L&F
            UIManager.setLookAndFeel(
                    UIManager.getSystemLookAndFeelClassName());
        } catch (UnsupportedLookAndFeelException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }

        //The main frame
        frame = new JFrame("Encrypted Message Server");
        frame.setSize(1000, 900);
        frame.setResizable(true);
        frame.setDefaultCloseOperation(EXIT_ON_CLOSE);
        frame.setLayout(new GridBagLayout());
        frame.addComponentListener(new Window()); //Window is defined further down. Mainly for doing stuff when the window is resized.

        //Creating the menu bar
        JMenuBar bar = new JMenuBar();
        JMenu fileMenu = new JMenu("File");
        JMenuItem helpItem = new JMenuItem("Help");
        helpItem.addActionListener(new HelpClickListener());
        fileMenu.add(helpItem);
        bar.add(fileMenu);
        frame.setJMenuBar(bar);

      /* The rest is to create the individual components and place them using gridbaglayout*/
        GridBagConstraints gbc = new GridBagConstraints();

        checkboxHeading = new JLabel("<html><b><u>Listen: </u></b></html>");
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(5, 10, 0, 0); //Padding
        gbc.gridwidth = 4;
        gbc.gridheight = 1;
        gbc.weighty = 0;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.BOTH;
        frame.add(checkboxHeading, gbc);

        gbc.insets = new Insets(0, 10, 10, 0); //Padding
        listenButton = new JButton("Listen");
        listenButton.addActionListener(new ConnectActionListener());
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        frame.add(listenButton, gbc);

        //Explanation area heading
        JLabel explanationHeading = new JLabel("<html><b><u>Messages received</u></b></html>");
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weighty = 0;
        gbc.insets = new Insets(0, 10, 2, 0); //Padding different for label
        gbc.gridheight = 1;
        gbc.gridwidth = 5;
        frame.add(explanationHeading, gbc);

        //The explanation area before the expressivity information
        receiveText = new JTextArea();
        receiveText.setEditable(false);
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 9;
        gbc.gridheight = 3;
        gbc.insets = new Insets(0, 10, 8, 0);
        gbc.weighty = 10;
        gbc.fill = GridBagConstraints.BOTH;
        frame.add(receiveText, gbc);

        JLabel sendMessageLabel = new JLabel("<html><b><u>Send Message: </u></b></html>");
        sendButton = new JButton("Send Message");
        sendButton.setEnabled(false);
        sendButton.addActionListener(new SendMessage());
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.weighty = 0;
        gbc.insets = new Insets(0, 10, 2, 0); //Padding different for label
        gbc.gridheight = 1;
        gbc.gridwidth = 2;

        //frame.add(sendMessageLabel, gbc);
        gbc.gridx = 0;
        frame.add(sendButton, gbc);


        gbc.insets = new Insets(0, 10, 8, 0); //Reset padding

        sendText = new JTextArea();
        sendText.setEditable(true);
        JScrollPane scroll = new JScrollPane(sendText);
        scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);

        //  expressivityPane.setSize(500,400);
        gbc.gridx = 0;
        gbc.gridy = 7;
        gbc.gridwidth = 9;
        gbc.gridheight = 1;
        gbc.weighty = 1;
        gbc.weightx = 1;
        gbc.fill = GridBagConstraints.BOTH;
        frame.add(scroll, gbc);

        frame.setVisible(true);
    }

    //On click for the 'Help' menu item
    private class HelpClickListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            HelpWindow window = new HelpWindow();
            window.setVisible(true);
        }
    }

    private class HelpWindow extends JFrame {
        public HelpWindow() {
            initialize();
        }

        //To close only this frame and not the main application
        WindowListener exitListener = new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                dispose();
            }
        };

        public void initialize() {
            setTitle("Help");
            setSize(400, 450);
            setResizable(false);
            setDefaultCloseOperation(DISPOSE_ON_CLOSE);
            addWindowListener(exitListener);

            JPanel panel = new JPanel();
            panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
            panel.setLayout(new BorderLayout());

            //The actual help text
            String text = "Help";
            JLabel info = new JLabel(text);
            info.setHorizontalAlignment(JLabel.CENTER);
            info.setVerticalAlignment(JLabel.CENTER);

            panel.add(info, BorderLayout.CENTER);

            add(panel);
        }
    }

    public String getTime() {
        DateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
        Date date = new Date();
        return dateFormat.format(date);
    }

    private class SendMessage implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {

            byte[] sendMessage;
            try {
                if(!sendText.getText().equals("")) {
                    sendMessage = sendText.getText().getBytes("UTF8");
                    receiveText.setText(receiveText.getText() + "\n" + getTime() + " " + sendText.getText());
                    serverSession.sendMessage(IVSecureRandom, serverPrivateKey, AESKey, usedNonces, sendMessage);
                    sendText.setText("");
                }
            } catch (UnsupportedEncodingException e1) {
                e1.printStackTrace();
            } catch (IOException e1) {
                e1.printStackTrace();
            }

        }
    }

    private class ConnectActionListener implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            Thread waitForConnectionThread = new Thread() {
                public void run() {
                    try {
                        serverSession = new ServerSession();
                        serverSession.waitForConnection();
                        receiveText.setText("Connected to client");

                        // ========== Fetch the message from the client ==========
                        byte[] receivedMessage = serverSession.pollForMessage();
                        int encryptedAESKeyLength = serverPublicKey.getModulus().bitLength() / 8;
                        byte[] encryptedKey = Arrays.copyOfRange(receivedMessage, 0, encryptedAESKeyLength);
                        byte[] AESKeyByteArray = RSA.decrypt(encryptedKey, serverPrivateKey, RSA_TRANSFORMATION);
                        System.out.println("Received message (Base64): " + Base64.getEncoder().encodeToString(receivedMessage));
                        System.out.println("Encrypted AES key (Base64): " + Base64.getEncoder().encodeToString(encryptedKey));
                        System.out.println("AES key (Base64): " + Base64.getEncoder().encodeToString(AESKeyByteArray));
                        AESKey = new SecretKeySpec(AESKeyByteArray, 0, AESKeyByteArray.length, "AES");

                        // ========== Random Salt ==========
                        int IVStartIndex = encryptedAESKeyLength;
                        byte[] nonce = Arrays.copyOfRange(receivedMessage, IVStartIndex, IVStartIndex + AESKeyByteArray.length);
                        String nonceTxt = Base64.getEncoder().encodeToString(nonce);
                        if (usedNonces.contains(nonceTxt)) {
                            System.out.println("Nonce has already been used, dropping message");
                            return;
                        }
                        System.out.println("Nonce (Base64): " + Base64.getEncoder().encodeToString(nonce));

                        // ========== Encrypted data ==========
                        int encryptedDataStartIndex = IVStartIndex + AESKeyByteArray.length;
                        byte[] encryptedData = Arrays.copyOfRange(receivedMessage, encryptedDataStartIndex, receivedMessage.length);
                        System.out.println("Encrypted data (Base64): " + Base64.getEncoder().encodeToString(encryptedData));

                        // ========== Decrypt message ==========
                        byte[] unencryptedData = AES.decrypt(encryptedData, AESKey, AES_TRANSFORMATION, nonce);
                        System.out.println("Unencrypted Data (Base64): " + Base64.getEncoder().encodeToString(unencryptedData));
                        byte[] unzippedData = ZIP.decompress(unencryptedData);
                        System.out.println("Unzipped Data (Base64): " + Base64.getEncoder().encodeToString(unzippedData));

                        // ========== Signature length ==========
                        ByteBuffer byteBuffer = ByteBuffer.wrap(Arrays.copyOfRange(unzippedData, 0, 4));
                        int signatureLength = byteBuffer.getInt();
                        System.out.println("Signature length: " + signatureLength);

                        // ========== Signature and verification ==========
                        byte[] signature = Arrays.copyOfRange(unzippedData, 4, 4 + signatureLength);
                        byte[] messageSection = Arrays.copyOfRange(unzippedData, 4 + signatureLength, unzippedData.length);
                        if (!DigitalSignature.verifySignature(messageSection, signature, clientPublicKey, SIGNATURE_TRANSFORMATION)) {
                            System.out.println("Signature does not match, ignoring message");
                            return;
                        }
                        usedNonces.add(nonceTxt);

                        // ========== Message ==========
                        byte[] messageContents = Arrays.copyOfRange(messageSection, 0, messageSection.length);
                        System.out.println("Message: " + new String(messageContents, "UTF8"));

                        // ========== Threads to allow sending and receiving of messages ==========
                        Thread receiveThread = new Thread() {
                            public void run() {
                                while (true) {
                                    try {
                                        byte[][] messages = serverSession.fetchMessages(AESKey, clientPublicKey, usedNonces);
                                        for (byte[] message : messages) {
                                            if (message != null) {
                                                receiveText.setText(receiveText.getText() + "\n" + getTime() + " Client: " + new String(message, "UTF8"));
                                            }
                                        }
                                        sleep(SLEEP_TIME);
                                    } catch (IOException | InterruptedException e) {
                                        e.printStackTrace();
                                    }
                                }
                            }
                        };
                        receiveThread.start();
                        listenButton.setText("Connected");
                        sendButton.setEnabled(true);
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    } catch (InterruptedException e1) {
                        e1.printStackTrace();
                    }
                }
            };
            listenButton.setEnabled(false);
            listenButton.setText("Listening");
            waitForConnectionThread.start();
        }
    }

    //For defining what happens when you resize the window
    private class Window implements ComponentListener {
        //Adjust sizes of whatever should change over here
        public void componentResized(ComponentEvent e) {

        }

        //The rest of the methods just need to be included for the sake of the interface
        public void paintComponent(Graphics g) {
        }

        public void componentHidden(ComponentEvent e) {
        }

        public void componentMoved(ComponentEvent e) {
        }

        public void componentShown(ComponentEvent e) {
        }
    }

    public static void main(String[] args) {
        ServerUI ui = new ServerUI();
    }
}