package session;

import encryption.AES;
import encryption.RSA;
import signature.DigitalSignature;
import storage.STORE;
import storage.StoreKeys;
import zipping.ZIP;

import java.awt.*;
import java.awt.event.*;
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
public class ClientUI extends JFrame {
    private JFrame frame;
    private JTextArea receiveText;
    private JTextField textField;
    private JButton sendButton;

    //Heading
    private JLabel connectLabel;
    private JTextArea sendText;
    ClientSession clientSession;

    private static final int AES_KEY_LENGTH = 128;

    Set<String> usedNonces = new HashSet<>();
    SecureRandom IVSecureRandom = new SecureRandom();

    // ========== RSA key exchange ==========
    // Read 2048 bit keys from storage
    KeyPair readKeyPair = STORE.readKeysFromPrivateKeyRing(StoreKeys.CLIENT_KEYID, StoreKeys.CLIENT_KEYS_FOLDER + StoreKeys.PRIVATE_KEY_RING_FILE_NAME);
    RSAPublicKey clientPublicKey = (RSAPublicKey) readKeyPair.getPublic();
    RSAPrivateKey clientPrivateKey = (RSAPrivateKey) readKeyPair.getPrivate();

    // Read server public key from file
    RSAPublicKey serverPublicKey = (RSAPublicKey) STORE.readKeyFromPublicKeyRing(StoreKeys.SERVER_KEYID, StoreKeys.CLIENT_KEYS_FOLDER + StoreKeys.PUBLIC_KEY_RING_FILE_NAME);

    // ========== AES key exchange ==========
    // Generate AES key
    Key AESKey = AES.generateKey(AES_KEY_LENGTH);

    //Constructor
    public ClientUI() {
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
        frame = new JFrame("Encrypted Message Client");
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

        connectLabel = new JLabel("<html><b><u>Connect: </u></b></html>");
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(5, 10, 0, 0); //Padding
        gbc.gridwidth = 4;
        gbc.gridheight = 1;
        gbc.weighty = 0;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.BOTH;
        frame.add(connectLabel, gbc);

        gbc.insets = new Insets(0, 10, 10, 0); //Padding
        textField = new JTextField("127.0.0.1", 20);
        JButton connect = new JButton("Connect");
        connect.addActionListener(new ConnectActionListener());
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        frame.add(textField, gbc);
        gbc.gridx = 2;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        frame.add(connect, gbc);

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
                    clientSession.sendMessage(IVSecureRandom, clientPrivateKey, AESKey, usedNonces, sendMessage);
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
            try {

                clientSession = new ClientSession(textField.getText());
                receiveText.setText(getTime() + ": Connected to server at " + textField.getText());
                System.out.println("Generated an AES key of " + AESKey.getEncoded().length * 8 + " bits");
                System.out.println("AES key (visualised as a base64 string): " + Base64.getEncoder().encodeToString(AESKey.getEncoded()));

                // Encrypt the AES key
                byte[] encryptedKey = RSA.encrypt(AESKey.getEncoded(), serverPublicKey, RSA_TRANSFORMATION);
                System.out.println("Encrypted AES key with server public key, length of encrypted key is " + encryptedKey.length * 8 + " bits");
                System.out.println("Encrypted AES key (Base64): " + Base64.getEncoder().encodeToString(encryptedKey));

                // Generate nonce / random salt - this can be sent as plaintext
                byte[] nonce;
                String nonceTxt;
                do {
                    nonce = AES.generateIV(IVSecureRandom, AES_KEY_LENGTH);
                    nonceTxt = Base64.getEncoder().encodeToString(nonce);
                } while (usedNonces.contains(nonceTxt));
                usedNonces.add(nonceTxt);
                System.out.println("Nonce generated (visualised as base64): " + nonceTxt);

                // ========== Hello Message ==========
                String text = "PGP Hello";
                byte[] clientMessage = text.getBytes("UTF8");
                System.out.println("Sending an initial hello message: " + text);

                // ========== Message contents ==========
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(clientMessage);
                byte[] messageContents = outputStream.toByteArray();
                System.out.println("Message contents, visualised as base64 string: " + Base64.getEncoder().encodeToString(messageContents));

                // ========== Signature ==========
                byte[] signature = DigitalSignature.generateSignature(messageContents, clientPrivateKey, SIGNATURE_TRANSFORMATION);
                System.out.println("Signature has " + signature.length + " bits");
                System.out.println("Signature (visualised as base64 String): " + Base64.getEncoder().encodeToString(signature));

                // ========== Concatenate signature and message ==========
                outputStream.reset();
                ByteBuffer byteBuffer = ByteBuffer.allocate(4);
                byteBuffer.putInt(signature.length);
                outputStream.write(byteBuffer.array());
                outputStream.write(signature);

                outputStream.write(messageContents);

                byte[] concatenatedSignatureAndMessage = outputStream.toByteArray();
                System.out.println("Concatenated signature and message (Base64): " + Base64.getEncoder().encodeToString(concatenatedSignatureAndMessage));
                System.out.println("Before zipping length: " + concatenatedSignatureAndMessage.length);
                byte[] zippedMessage = ZIP.compress(concatenatedSignatureAndMessage);
                System.out.println("After zipping length: " + zippedMessage.length);
                System.out.println("Zipped message (Base64): " + Base64.getEncoder().encodeToString(zippedMessage));

                byte[] encryptedMessage = AES.encrypt(zippedMessage, AESKey, AES_TRANSFORMATION, nonce);
                System.out.println("Encrypted message (Base64): " + Base64.getEncoder().encodeToString(encryptedMessage));

                // ========== Final message construction ==========
                outputStream.reset();

                outputStream.write(encryptedKey);
                outputStream.write(nonce);
                outputStream.write(encryptedMessage);
                byte[] output = outputStream.toByteArray();

                clientSession.sendMessage(output);

                Thread receiveThread = new Thread() {
                    public void run() {
                        while (true) {
                            try {
                                byte[][] messages = clientSession.fetchMessages(AESKey, serverPublicKey, usedNonces);
                                for (byte[] message : messages) {
                                    if (message != null) {
                                        receiveText.setText(receiveText.getText() + "\n" + getTime() + " Server: " + new String(message, "UTF8"));
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
                sendButton.setEnabled(true);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
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
        ClientUI ui = new ClientUI();
    }
}