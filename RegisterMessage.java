import java.io.Serializable;

public class RegisterMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    public final String clientId;
    public final byte[] publicKeyEncoded;

    public RegisterMessage(String clientId, byte[] publicKeyEncoded) {
        this.clientId = clientId;
        this.publicKeyEncoded = publicKeyEncoded;
    }
}
