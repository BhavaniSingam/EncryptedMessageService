package session;

import encryption.AES;
import storage.STORE;
import storage.StoreKeys;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static session.Session.SLEEP_TIME;

/**
 * UI for the client
 *
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
    private Set<String> usedNonces;
    private SecureRandom IVSecureRandom;
    private RSAPublicKey clientPublicKey;
    private RSAPrivateKey clientPrivateKey;
    private RSAPublicKey serverPublicKey;


    //Constructor
    public ClientUI() {
        // Initialise components
        usedNonces = new HashSet<>();
        IVSecureRandom = new SecureRandom();

        // ========== RSA key exchange ==========
        // Read 2048 bit keys from storage
        KeyPair readKeyPair = STORE.readKeysFromPrivateKeyRing(StoreKeys.CLIENT_KEYID, StoreKeys.CLIENT_KEYS_FOLDER + StoreKeys.PRIVATE_KEY_RING_FILE_NAME);
        clientPublicKey = (RSAPublicKey) readKeyPair.getPublic();
        clientPrivateKey = (RSAPrivateKey) readKeyPair.getPrivate();

        // Read server public key from file
        serverPublicKey = (RSAPublicKey) STORE.readKeyFromPublicKeyRing(StoreKeys.SERVER_KEYID, StoreKeys.CLIENT_KEYS_FOLDER + StoreKeys
                .PUBLIC_KEY_RING_FILE_NAME);

        initialize();
    }

    private void initiateConnection() throws IOException {
        clientSession = new ClientSession(textField.getText());
        receiveText.setText(getTime() + ": Connected to server at " + textField.getText());

        clientSession.setLocalPrivateKey(clientPrivateKey);
        clientSession.setLocalPublicKey(clientPublicKey);
        clientSession.setRemotePublicKey(serverPublicKey);
        clientSession.setAESKey(AES.generateKey(AES_KEY_LENGTH));
        byte[] output = clientSession.encryptHandshakeMessage(StoreKeys.SERVER_KEYID, StoreKeys.CLIENT_KEYID, IVSecureRandom, usedNonces);

        clientSession.sendMessage(output);
        System.out.println();

        Thread receiveThread = new Thread() {
            public void run() {
                while (true) {
                    try {
                        byte[][] messages = clientSession.fetchMessages(serverPublicKey, usedNonces);
                        for (byte[] message : messages) {
                            if (message != null) {
                                addToChatWindow("\n" + getTime() + " Server: " + new String(message, "UTF8"));
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
    }

    private synchronized void addToChatWindow(String text) {
        receiveText.setText(receiveText.getText() + text);
    }

    private class SendMessage implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            byte[] sendMessage;
            try {
                if (!sendText.getText().equals("")) {
                    String text = sendText.getText();
                    sendMessage = text.getBytes("UTF8");
                    System.out.println("Message to send: " + text);
                    addToChatWindow("\n" + getTime() + " " + text);
                    clientSession.sendMessage(IVSecureRandom, clientPrivateKey, usedNonces, sendMessage);
                    sendText.setText("");
                    System.out.println();
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
                initiateConnection();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
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