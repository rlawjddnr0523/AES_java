package gen1;

import static gen1.functions.AESKeyGenerator.generateRandomAESKey;
import static gen1.functions.KeyScedule.keySchedule;
import static gen1.table.Sbox.INV_SBOX;
import static gen1.table.Sbox.sbox;

import java.util.Arrays;
import java.util.Scanner;

public class AES {
    public static void main(String[] args) {
//        Scanner sc = new Scanner(System.in);
//        System.out.print("32자리 16진수 입력: ");
//        String input = sc.nextLine().trim();
//
//        if(input.length() != 32) {
//            System.out.println("길이 오류: 32자리 16진수만 입력 가능");
//            return;
//        }
//        if(!input.matches("[0-9a-fA-F]+")) {
//            System.out.println("16진수 문자만 입력 가능");
//            return;
//        }
//
//        byte[] Plain = hexStringToByteArray(input);
        byte[] Plain = new byte[] {
                (byte)0x32, (byte)0x43, (byte)0xf6, (byte)0xa8
                , (byte)0x88, (byte)0x5a, (byte)0x30, (byte)0x8d
                , (byte)0x31, (byte)0x31, (byte)0x98, (byte)0xa2
                , (byte)0xe0, (byte)0x37, (byte)0x07, (byte)0x34
        };
//        byte[] Plain = new byte[] {
//                (byte)0x32, (byte)0x43, (byte)0xf6, (byte)0xa8
//                , (byte)0x88, (byte)0x5a, (byte)0x30, (byte)0x8d
//                , (byte)0x31, (byte)0x31, (byte)0x98, (byte)0xa2
//                , (byte)0xe0, (byte)0x37, (byte)0x07, (byte)0x34
//        };
        byte[] key = generateRandomAESKey();
//        byte[] key = new byte[] {
//                (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
//                (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
//                (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
//                (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
//        };
        
        byte[] enc = ECBEncrypt(Plain, key);
        System.out.println("암호화: "+bytesToHex(enc));
        
        byte[] dec = ECBDecrypt(enc, key);
        System.out.println("복호화: "+bytesToHex(dec));
        System.out.println("평문: "+bytesToHex(Plain));
        System.out.println("키: "+bytesToHex(key));
    }
    
    public static byte[] ECBEncrypt(byte[] plain, byte[] key) {
        byte[] roundKey = keySchedule(4, key);
        
        byte[] res = addRoundKey(plain, getRoundKey(roundKey, 0));
        
        for (int i = 1; i < 10; i++) {
            res = addRoundKey(mixColumns(shiftRows(subBytes(res))), getRoundKey(roundKey, i));
        }
        
        res = addRoundKey(shiftRows(subBytes(res)), getRoundKey(roundKey, 10));
        
//        System.out.println(bytesToHex(getRoundKey(roundKey, 10)));
        
        return res;
    }
    
    public static byte[] ECBDecrypt(byte[] cipher, byte[] key) {
        byte[] roundKey = keySchedule(4, key);
        
        byte[] res = addRoundKey(cipher, getRoundKey(roundKey, 10));
        
        for (int i = 9; i > 0; i--) {
            res = invMixColumns(addRoundKey(invSubBytes(invShiftRows(res)), getRoundKey(roundKey, i)));
        }
        
        res = addRoundKey(invSubBytes(invShiftRows(res)), getRoundKey(roundKey, 0));
        
        return res;
    }
    
    public static byte[] mixColumns(byte[] input) {
        byte[] output = new byte[16];
        
        for (int col = 0; col < 4; col++) {
            int base = col * 4;
            byte s0 = input[base];
            byte s1 = input[base + 1];
            byte s2 = input[base + 2];
            byte s3 = input[base + 3];
            
            output[base]     = (byte) (mul(s0, 2) ^ mul(s1, 3) ^ mul(s2, 1) ^ mul(s3, 1));
            output[base + 1] = (byte) (mul(s0, 1) ^ mul(s1, 2) ^ mul(s2, 3) ^ mul(s3, 1));
            output[base + 2] = (byte) (mul(s0, 1) ^ mul(s1, 1) ^ mul(s2, 2) ^ mul(s3, 3));
            output[base + 3] = (byte) (mul(s0, 3) ^ mul(s1, 1) ^ mul(s2, 1) ^ mul(s3, 2));
        }
        
        return output;
    }
    
    public static byte[] invMixColumns(byte[] state) {
        byte[] output = new byte[16];
        for (int c = 0; c < 4; c++) {
            int i = c * 4;
            byte s0 = state[i];
            byte s1 = state[i + 1];
            byte s2 = state[i + 2];
            byte s3 = state[i + 3];
            
            output[i]     = (byte) (gfMul((byte)0x0e, s0) ^ gfMul((byte)0x0b, s1) ^ gfMul((byte)0x0d, s2) ^ gfMul((byte)0x09, s3));
            output[i + 1] = (byte) (gfMul((byte)0x09, s0) ^ gfMul((byte)0x0e, s1) ^ gfMul((byte)0x0b, s2) ^ gfMul((byte)0x0d, s3));
            output[i + 2] = (byte) (gfMul((byte)0x0d, s0) ^ gfMul((byte)0x09, s1) ^ gfMul((byte)0x0e, s2) ^ gfMul((byte)0x0b, s3));
            output[i + 3] = (byte) (gfMul((byte)0x0b, s0) ^ gfMul((byte)0x0d, s1) ^ gfMul((byte)0x09, s2) ^ gfMul((byte)0x0e, s3));
        }
        return output;
    }
    
    public static byte[] shiftRows(byte[] val) {
        byte[][] state = new byte[4][4];
        
        // 1. 1차원 배열을 4x4 상태 행렬로 변환 (열 우선)
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] = val[col * 4 + row];
            }
        }
        
        // 2. 행 번호만큼 왼쪽으로 순환 시프트
        for (int row = 1; row < 4; row++) {
            byte[] temp = new byte[4];
            for (int col = 0; col < 4; col++) {
                temp[col] = state[row][(col + row) % 4];
            }
            state[row] = temp;
        }
        
        // 3. 다시 1차원 배열로 평탄화
        byte[] output = new byte[16];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                output[col * 4 + row] = state[row][col];
            }
        }
        
        return output;
    }
    
    public static byte[] invShiftRows(byte[] state) {
        byte[] output = new byte[16];
        
        output[0] = state[0];
        output[4] = state[4];
        output[8] = state[8];
        output[12] = state[12];
        
        output[1] = state[13];
        output[5] = state[1];
        output[9] = state[5];
        output[13] = state[9];
        
        output[2] = state[10];
        output[6] = state[14];
        output[10] = state[2];
        output[14] = state[6];
        
        output[3] = state[7];
        output[7] = state[11];
        output[11] = state[15];
        output[15] = state[3];
        
        return output;
    }
    
    public static byte[] subBytes(byte[] val) {
        for (int i = 0; i < val.length; i++) {
            val[i] = sbox[val[i] & 0xff];
        }
        return val;
    }
    
    public static byte[] invSubBytes(byte[] state) {
        byte[] output = new byte[16];
        for (int i = 0; i < 16; i++) {
            int index = state[i] & 0xFF;  // 바이트 값을 0~255로 변환
            output[i] = INV_SBOX[index];
        }
        return output;
    }
    
    public static byte[] addRoundKey(byte[] state, byte[] roundKey) {
        byte[] res = new byte[16];
        for (int i = 0; i < 16; i++) {
            res[i] = (byte)(state[i] ^ roundKey[i]);
        }
        return res;
    }
    
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i]));
            if (i < bytes.length - 1) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }
    
    public static byte[] CircLShift(byte[] fbyte) {
        byte[] res = new byte[4];
        res[0] = fbyte[1];
        res[1] = fbyte[2];
        res[2] = fbyte[3];
        res[3] = fbyte[0];
        
        return res;
    }
    
    public static byte[] getRoundKey(byte[] expandedKey, int round) {
        if ((round + 1) * 16 > expandedKey.length) {
            throw new IllegalArgumentException("Round number too high for given key.");
        }
        byte[] roundKey = new byte[16];
        System.arraycopy(expandedKey, round * 16, roundKey, 0, 16);
        return roundKey;
    }
    
    private static byte xtime(byte x) {
        return (byte) ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
    }
    
    private static byte mul(byte x, int mul) {
        return switch (mul) {
            case 1 -> x;
            case 2 -> xtime(x);
            case 3 -> (byte) (xtime(x) ^ x);
            default -> throw new IllegalArgumentException("Invalid multiplier");
        };
    }
    
    private static byte gfMul(byte a, byte b) {
        byte res = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                res ^= a;
            }
            boolean highBitSet = (a & 0x80) != 0;
            a <<= 1;
            if (highBitSet) {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        return res;
    }
    
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for(int i = 0; i < len; i += 2) {
            data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
