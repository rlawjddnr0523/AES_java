package gen1.tests;

import static gen1.AES.ECBDecrypt;
import static gen1.AES.ECBEncrypt;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

public class AESTest {
    
    @Test
    public void testAESEncryption() {
        // FIPS 197, Advanced Encryption Standard (AES)
        // Appendix B - Cipher Example (128)
        
        // (hex) 32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34
        byte[] Plain = new byte[] {
                (byte)0x32, (byte)0x43, (byte)0xf6, (byte)0xa8
                , (byte)0x88, (byte)0x5a, (byte)0x30, (byte)0x8d
                , (byte)0x31, (byte)0x31, (byte)0x98, (byte)0xa2
                , (byte)0xe0, (byte)0x37, (byte)0x07, (byte)0x34
        };
        
        // (hex) 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C
        byte[] key = new byte[] {
                (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
                (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
                (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
                (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };
        
        // (hex) 39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32
        byte[] cipher = new byte[]{
                (byte) 0x39, (byte) 0x25, (byte) 0x84, (byte) 0x1D,
                (byte) 0x02, (byte) 0xDC, (byte) 0x09, (byte) 0xFB,
                (byte) 0xDC, (byte) 0x11, (byte) 0x85, (byte) 0x97,
                (byte) 0x19, (byte) 0x6A, (byte) 0x0B, (byte) 0x32
        };
        
//        System.out.println(Arrays.toString(Plain));
        
        byte[] res = ECBEncrypt(Plain, key);
        assertArrayEquals(cipher, res, "AES Encryption Failed❌");
        System.out.println("암호화 테스트를 통과했습니다 ✅: \n"+Arrays.toString(cipher) +"\n위 ⬆️ 값과 아래 ⬆️ 값이 같기 때문에 이 테스트를 통과하였습니다.\n"+Arrays.toString(res));
        System.out.println("----------------------------------------------------------------------");
        byte[] dec = ECBDecrypt(cipher, key);
        assertArrayEquals(Plain, dec, "AES Decryption Failed❌");
        System.out.println("복호화 테스트를 통과했습니다 ✅: \n"+Arrays.toString(Plain)+"\n위 ⬆️ 값과 아래 ⬇️ 값이 같기 때문에 이 테스트를 통과하였습니다.\n"+Arrays.toString(dec));
    }
    
    @Test
    public void tmp() throws Exception {
        // 1. 16진 문자열을 바이트 배열로 변환
        byte[] plaintext = hexStringToByteArray("3243f6a8885a308d313198a2e0370734");
        byte[] keyBytes  = hexStringToByteArray("2b7e151628aed2a6abf7158809cf4f3c");
        
        // 2. AES 키 스펙 정의
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        
        // 3. AES/ECB/PKCS5Padding 모드로 Cipher 생성
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        // 4. 암호화 실행
        byte[] encrypted = cipher.doFinal(plaintext);
        
        // 5. 출력 (HEX 또는 Base64)
        System.out.println("Encrypted (HEX): " + bytesToHex(encrypted));
        System.out.println("Encrypted (Base64): " + Base64.getEncoder().encodeToString(encrypted));
    }
    
    // 헥스트링 -> 바이트 배열
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte)
                    ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
    // 바이트 배열 -> 헥스트링
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
