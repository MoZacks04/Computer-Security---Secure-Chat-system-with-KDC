import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class ReplayCache {
    private final Set<String> seen = Collections.synchronizedSet(new HashSet<>());

    public boolean alreadySeen(String senderId, String nonce) {
        String key = senderId + "|" + nonce;
        if (seen.contains(key)) {
            return true;
        }
        seen.add(key);
        return false;
    }
}
