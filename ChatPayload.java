import java.io.Serializable;

public class ChatPayload implements Serializable {
    private static final long serialVersionUID = 1L;

    public final String senderId;
    public final long timestamp;
    public final String nonce;
    public final String message;

    public ChatPayload(String senderId, long timestamp, String nonce, String message) {
        this.senderId = senderId;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.message = message;
    }
}
