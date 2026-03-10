import java.io.Serializable;

public class ChatPacket implements Serializable {
    private static final long serialVersionUID = 1L;

    public final String senderId;
    public final byte[] iv;
    public final byte[] ciphertext;
    public final byte[] signature;

    public ChatPacket(String senderId, byte[] iv, byte[] ciphertext, byte[] signature) {
        this.senderId = senderId;
        this.iv = iv;
        this.ciphertext = ciphertext;
        this.signature = signature;
    }
}
