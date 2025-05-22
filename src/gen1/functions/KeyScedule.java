package gen1.functions;

import static gen1.AES.CircLShift;
import static gen1.AES.bytesToHex;
import static gen1.AES.getRoundKey;
import static gen1.functions.AESKeyGenerator.generateRandomAESKey;
import static gen1.table.RoundConstant.RCON;
import static gen1.table.Sbox.sbox;

import java.util.Arrays;

public class KeyScedule {
    public static byte[] keySchedule(int Nk, byte[] KEY) {
        int Nr = 10;  // AES-128 고정
        int Nb = 4;   // AES 블록 크기 128비트 -> 4워드
        
        int totalWords = Nb * (Nr + 1);  // 44개 워드 생성
        byte[][] w = new byte[totalWords][4];  // 각 워드는 4바이트
        
        // 1. 초기 Nk개 워드 복사 (원본 키)
        byte[][] splitKey = splitIntoWords(KEY);
        for (int i = 0; i < Nk; i++) {
            w[i] = splitKey[i];
        }
        
        // 2. 나머지 워드 생성
        for (int i = Nk; i < totalWords; i++) {
            byte[] temp = w[i - 1].clone();
            
            if (i % Nk == 0) {
                temp = getTi(temp, i / Nk);  // RotWord + SubWord + RCON 적용
            }
            // AES-256 같은 경우 추가 조건 필요하지만 AES-128은 생략 가능
            
            w[i] = xorWords(w[i - Nk], temp);
        }
        
        // 3. 1차원 배열로 펼치기
        byte[] expandedKey = new byte[totalWords * 4];
        for (int i = 0; i < totalWords; i++) {
            System.arraycopy(w[i], 0, expandedKey, i * 4, 4);
        }
        
        return expandedKey;
    }
    
    public static byte[] xorWords(byte[] a, byte[] b) {
        byte[] res = new byte[4];
        for (int i = 0; i < 4; i++) {
            res[i] = (byte)(a[i] ^ b[i]);
        }
        return res;
    }
    
    public static byte[] getTi(byte[] key, int round) {
        byte[] rotatedKey = CircLShift(key);
        
//        System.out.println("after Rotate: "+bytesToHex(rotatedKey));
        
        for (int i = 0; i < 4; i++) {
            rotatedKey[i] = sbox[rotatedKey[i] & 0xff];
        }
        
//        System.out.println("after Sbox: "+bytesToHex(rotatedKey));
//        System.out.println("Round Constant: "+bytesToHex(RCON[round]));
        
        rotatedKey[0] = (byte)(rotatedKey[0] ^ RCON[round][0]);
        
//        System.out.println("after RCon: "+bytesToHex(rotatedKey));
        
        return rotatedKey;
    }
    
    public static byte[][] splitIntoWords(byte[] input) {
        if (input.length != 16) {
            throw new IllegalArgumentException("Input must be 16 bytes.");
        }
        
        byte[][] words = new byte[4][4]; // 4개 워드, 각 워드당 4바이트
        
        for (int i = 0; i < 4; i++) {
            System.arraycopy(input, i * 4, words[i], 0, 4);
        }
        
//        System.out.println(bytesToHex(input));
        return words;
    }
    
    public static void main(String[] args) {
//        byte[][] KEY = splitIntoWords(generateRandomAESKey());
        byte[] key = new byte[] {
                (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
                (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
                (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
                (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };
        byte[] roundKeys = keySchedule(4, key);
        for (int i = 0; i <= 10; i++) {
            byte[] roundK = getRoundKey(roundKeys, i);
            System.out.printf("%d라운드키: %s\n", i, bytesToHex(roundK));
        }
    }
}
