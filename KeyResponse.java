import java.io.Serializable;
import java.util.Map;

public class KeyResponse implements Serializable {
    private static final long serialVersionUID = 1L;

    public final byte[] encryptedGroupKey;
    public final byte[] kdcSignature;
    public final byte[] kdcPublicKeyEncoded;
    public final Map<String, byte[]> allClientPublicKeys;

    public KeyResponse(byte[] encryptedGroupKey,
                       byte[] kdcSignature,
                       byte[] kdcPublicKeyEncoded,
                       Map<String, byte[]> allClientPublicKeys) {
        this.encryptedGroupKey = encryptedGroupKey;
        this.kdcSignature = kdcSignature;
        this.kdcPublicKeyEncoded = kdcPublicKeyEncoded;
        this.allClientPublicKeys = allClientPublicKeys;
    }
}
