import javax.crypto.SecretKey;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class KDCServer {

    private static final int PORT = 5000;

    private final Map<String, ClientHandler> clients = new ConcurrentHashMap<>();
    private final Map<String, PublicKey> clientPublicKeys = new ConcurrentHashMap<>();

    private KeyPair kdcKeyPair;
    private SecretKey groupKey;
    private volatile boolean groupKeyDistributed = false;

    public static void main(String[] args) throws Exception {
        new KDCServer().start();
    }

    public void start() throws Exception {
        kdcKeyPair = CryptoUtil.generateRSAKeyPair();
        System.out.println("KDC started on port " + PORT);

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                Socket socket = serverSocket.accept();
                ClientHandler handler = new ClientHandler(socket);
                handler.start();
            }
        }
    }

    private synchronized void tryDistributeGroupKey() throws Exception {
        if (groupKeyDistributed) return;
        if (clients.size() < 3) return;

        groupKey = CryptoUtil.generateAESKey();
        byte[] groupKeyBytes = groupKey.getEncoded();

        Map<String, byte[]> allPub = new ConcurrentHashMap<>();
        for (Map.Entry<String, PublicKey> e : clientPublicKeys.entrySet()) {
            allPub.put(e.getKey(), e.getValue().getEncoded());
        }

        System.out.println("\nAll 3 clients connected. Distributing shared group key Ks...\n");

        for (Map.Entry<String, ClientHandler> entry : clients.entrySet()) {
            String clientId = entry.getKey();
            ClientHandler handler = entry.getValue();
            PublicKey clientPub = clientPublicKeys.get(clientId);

            byte[] encryptedKs = CryptoUtil.rsaEncrypt(groupKeyBytes, clientPub);
            byte[] sig = CryptoUtil.sign(encryptedKs, kdcKeyPair.getPrivate());

            KeyResponse response = new KeyResponse(
                    encryptedKs,
                    sig,
                    kdcKeyPair.getPublic().getEncoded(),
                    allPub
            );

            handler.send(response);
            System.out.println("Sent Ks to client " + clientId);
        }

        groupKeyDistributed = true;
        System.out.println("\nKDC setup complete. Ready to forward chat packets.\n");
    }

    private void forwardToOthers(ChatPacket packet) {
        for (Map.Entry<String, ClientHandler> entry : clients.entrySet()) {
            String targetId = entry.getKey();
            if (!targetId.equals(packet.senderId)) {
                entry.getValue().send(packet);
                System.out.println("KDC forwarded message from " + packet.senderId + " to " + targetId);
            }
        }
    }

    private class ClientHandler extends Thread {
        private final Socket socket;
        private ObjectOutputStream out;
        private ObjectInputStream in;
        private String clientId;

        ClientHandler(Socket socket) {
            this.socket = socket;
        }

        void send(Object obj) {
            try {
                synchronized (out) {
                    out.writeObject(obj);
                    out.flush();
                }
            } catch (Exception e) {
                System.out.println("Failed sending to " + clientId + ": " + e.getMessage());
            }
        }

        @Override
        public void run() {
            try {
                out = new ObjectOutputStream(socket.getOutputStream());
                out.flush();
                in = new ObjectInputStream(socket.getInputStream());

                Object first = in.readObject();
                if (!(first instanceof RegisterMessage)) {
                    throw new RuntimeException("Expected RegisterMessage first.");
                }

                RegisterMessage reg = (RegisterMessage) first;
                clientId = reg.clientId;

                clients.put(clientId, this);
                clientPublicKeys.put(clientId, CryptoUtil.bytesToPublicKey(reg.publicKeyEncoded));

                System.out.println("Client " + clientId + " connected and registered.");
                tryDistributeGroupKey();

                while (true) {
                    Object obj = in.readObject();
                    if (obj instanceof ChatPacket) {
                        ChatPacket packet = (ChatPacket) obj;
                        forwardToOthers(packet);
                    }
                }

            } catch (Exception e) {
                System.out.println("Connection closed for " + clientId + ": " + e.getMessage());
            } finally {
                try {
                    if (clientId != null) {
                        clients.remove(clientId);
                        clientPublicKeys.remove(clientId);
                    }
                    socket.close();
                } catch (Exception ignored) {
                }
            }
        }
    }
}
