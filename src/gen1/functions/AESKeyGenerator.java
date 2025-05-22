package gen1.functions;

import java.security.SecureRandom;

public class AESKeyGenerator {
    public static byte[] generateRandomAESKey() {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[16];
        random.nextBytes(key);
        return key;
    }
}
