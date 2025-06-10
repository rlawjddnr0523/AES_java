import java.io.IOException;
import java.nio.file.*;

public class Functions {
    /**
     * 암호화 메소드
     * Encryption Method
     * @param S PlainText Input ( byte[][] )
     * @param K Key Input ( byte[] )
     * @param Nr Number of Rounds ( int )
     * @param Nk Key Length ( int )
     * @param Nb Amount of Things in each Block ( int )
     * @see #subBytes(byte[][])
     * @see #shiftRows(byte[][])
     * @see #mixColumns(byte[][])
     * @see #addRoundKey(byte[][], int[], int, int)
     * @see #keySchedule(byte[], int, int, int)
     */
    public static void Encrypt(byte[][] S, byte[] K, int Nr, int Nk, int Nb) {
        
        // 키 확장을 통하여 라운드키 생성
        int[] roundKey = Functions.keySchedule(K, Nr, Nk, Nb);
        
        // 0 라운드
        Functions.addRoundKey(S, roundKey, 0, Nb);
        
        for (int round = 1; round < Nr; round++) {
            // 1 라운드 부터 Nr-1 라운드까지 반복
            Functions.subBytes(S); Functions.shiftRows(S); Functions.mixColumns(S); Functions.addRoundKey(S, roundKey, round, Nb);
        }
        // Nr 라운드 ( 마지막 라운드 수행 )
        Functions.subBytes(S); Functions.shiftRows(S); Functions.addRoundKey(S, roundKey, Nr, Nb);
    }
    
    /**
     * 복호화 메소드 Decryption Method
     * @param S State Input
     * @param K Secure Key Input
     * @param Nr Number of Rounds
     * @param Nk Key Length
     * @param Nb Block size
     * @see #invSubBytes(byte[][])
     * @see #invShiftRows(byte[][])
     * @see #invMixColumns(byte[][])
     * @see #addRoundKey(byte[][], int[], int, int)
     * @see #keySchedule(byte[], int, int, int)
     */
    public static void Decrypt(byte[][] S, byte[] K, int Nr, int Nk, int Nb) {
        
        // 라운드 키 생성
        int[] roundKey = Functions.keySchedule(K, Nr, Nk, Nb);
        
        // Nr 라운드 역순으로 진행
        Functions.addRoundKey(S, roundKey, Nr, Nb);
        
        // Nr-1 라운드부터 1라운드 까지 반복
        for (int i = Nr-1; i > 0; i--) {
            Functions.invShiftRows(S); Functions.invSubBytes(S); Functions.addRoundKey(S, roundKey, i, Nb); Functions.invMixColumns(S);
        }
        
        // 0 라운드 (마지막)
        Functions.invShiftRows(S); Functions.invSubBytes(S); Functions.addRoundKey(S, roundKey, 0, Nb);
    }
    
    /**
     * S-Box 적용 subBytes 메소드 <br/>
     * subBytes Method that applys S-Box
     * @param S State Input
     * @see Table#sBox
     */
    public static void subBytes(byte[][] S) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                int tmp = S[r][c] & 0xff;
                int first = (tmp >> 4) & 0x0f;
                int second = tmp & 0x0f;
                S[r][c] = Table.sBox[first][second];
            }
        }
    }
    
    /**
     * 왼쪽으로 순환 쉬프트하는 shiftRows 메소드 <br>
     * Method shiftRows that circular shift left
     * @param S State Input
     */
    public static void shiftRows(byte[][] S) {
        for (int row = 1; row < 4; row++) {
            byte[] newRow = new byte[4];
            for (int col = 0; col < 4; col++) {
                newRow[col] = S[row][(col + row) % 4];
            }
            S[row] = newRow;
        }
    }
    
    /**
     * 갈루아 필드를 사용한 연산을 수행하는 mixColumns 메소드 <br>
     * Method mixColumns that applys GF(2^8)
     * @param S State Input
     * @see #gfMul(int, byte)
     */
    public static void mixColumns(byte[][] S) {
        byte[][] tmp = new byte[4][4];
        for (int c = 0; c < 4; c++) {
            tmp[0][c] = (byte) (gfMul(0x02, S[0][c]) ^ gfMul(0x03, S[1][c]) ^ S[2][c] ^ S[3][c]);
            tmp[1][c] = (byte) (S[0][c] ^ gfMul(0x02, S[1][c]) ^ gfMul(0x03, S[2][c]) ^ S[3][c]);
            tmp[2][c] = (byte) (S[0][c] ^ S[1][c] ^ gfMul(0x02, S[2][c]) ^ gfMul(0x03, S[3][c]));
            tmp[3][c] = (byte) (gfMul(0x03, S[0][c]) ^ S[1][c] ^ S[2][c] ^ gfMul(0x02, S[3][c]));
        }
        for (int c = 0; c < 4; c++) {
            S[0][c] = tmp[0][c];
            S[1][c] = tmp[1][c];
            S[2][c] = tmp[2][c];
            S[3][c] = tmp[3][c];
        }
    }
    
    /**
     * 복호화시 사용하는 invSubBytes 메소드 <br>
     * Method invSubBytes that use when decipher.
     * @param S State Input
     * @see Table#invSbox
     */
    public static void invSubBytes(byte[][] S) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                int tmp = S[r][c] & 0xff;
                int first = (tmp >> 4) & 0x0f;
                int second = tmp & 0x0f;
                S[r][c] = Table.invSbox[first][second];
            }
        }
    }
    
    /**
     * 복호화시 사용하는 invShiftRows 메소드. 역방향으로 순환 쉬프트 한다.
     * @param S State Input
     * @see <a href="https://csrc.nist.gov/pubs/fips/197/final">FIPS-197</a>
     */
    public static void invShiftRows(byte[][] S) {
        for (int row = 1; row < 4; row++) {
            byte[] newRow = new byte[4];
            for (int col = 0; col < 4; col++) {
                newRow[col] = S[row][(col - row + 4) % 4];
            }
            S[row] = newRow;
        }
    }
    
    /**
     * 복호화시 사용하는 invMixColumns 메소드.
     * @param S State Input
     * @see #mul(int, byte)
     * @see #xtime(int, int)
     */
    public static void invMixColumns(byte[][] S) {
        byte[][] tmp = new byte[4][4];
        for (int c = 0; c < 4; c++) {
            tmp[0][c] = (byte) (mul(0x0e, S[0][c]) ^ mul(0x0b, S[1][c]) ^ mul(0x0d, S[2][c]) ^ mul(0x09, S[3][c]));
            tmp[1][c] = (byte) (mul(0x09, S[0][c]) ^ mul(0x0e, S[1][c]) ^ mul(0x0b, S[2][c]) ^ mul(0x0d, S[3][c]));
            tmp[2][c] = (byte) (mul(0x0d, S[0][c]) ^ mul(0x09, S[1][c]) ^ mul(0x0e, S[2][c]) ^ mul(0x0b, S[3][c]));
            tmp[3][c] = (byte) (mul(0x0b, S[0][c]) ^ mul(0x0d, S[1][c]) ^ mul(0x09, S[2][c]) ^ mul(0x0e, S[3][c]));
        }
        for (int c = 0; c < 4; c++) {
            S[0][c] = tmp[0][c];
            S[1][c] = tmp[1][c];
            S[2][c] = tmp[2][c];
            S[3][c] = tmp[3][c];
        }
    }
    
    /**
     * State와 라운드키랑 XOR 연산을 수행하는 addRoundKey 메소드
     * @param S State Input
     * @param K Key
     * @param round Round Value
     * @param Nb Fixed value 4
     */
    public static void addRoundKey(byte[][] S, int[] K, int round, int Nb) {
        int l = round * Nb;
        for (int c = 0; c < Nb; c++) {
            int word = K[l + c];
            S[0][c] ^= (byte) ((word >>> 24) & 0xFF);
            S[1][c] ^= (byte) ((word >>> 16) & 0xFF);
            S[2][c] ^= (byte) ((word >>> 8) & 0xFF);
            S[3][c] ^= (byte) (word & 0xFF);
        }
    }
    
    /**
     * 보안 키를 확장하여 라운드키를 생성하는 keySchedule(keyExpansion) 함수
     * @param K Key Input
     * @param Nr Number of Rounds
     * @param Nk Key Length
     * @param Nb Fixed value 4
     * @return roundKey [Nb * (Nr + 1)]
     * @see #rotWord(int)
     * @see #subWord(int)
     * @see Table#RCon
     */
    public static int[] keySchedule(byte[] K, int Nr, int Nk, int Nb) {
        int[] w = new int[Nb * (Nr + 1)];
        int tmp;
        
        for (int i = 0; i < Nk; i++) {
            w[i] =  ((K[4 * i] & 0xff) << 24) |
                    ((K[4 * i + 1] & 0xff) << 16) |
                    ((K[4 * i + 2] & 0xff) << 8) |
                    (K[4 * i + 3] & 0xff);
        }
        
        for (int i = Nk; i < Nb * (Nr + 1); i++) {
            tmp = w[i - 1];
            if (i % Nk == 0) {
                tmp = rotWord(tmp);
                tmp = subWord(tmp);
                tmp = (Table.RCon[i / Nk] << 24) ^ tmp;
            } else if (Nk > 6 && (i % Nk == 4)) {
                tmp = subWord(tmp);
            }
            w[i] = w[i - Nk] ^ tmp;
        }
        
        return w;
    }
    
    /**
     * Galois Field (2^8) 연산을 수행하는 함수
     * @param a value 1
     * @param b value 2
     * @return Result
     */
    private static byte gfMul(int a, byte b) {
        int res = 0;
        int bb = b & 0xFF;
        for (int i = 0; i < 8; i++) {
            if ((a & 1) != 0) {
                res ^= bb;
            }
            boolean highBitSet = (bb & 0x80) != 0;
            bb <<= 1;
            if (highBitSet) {
                bb ^= 0x1b; // AES의 irreducible polynomial: x^8 + x^4 + x^3 + x + 1
            }
            a >>= 1;
        }
        return (byte) (res & 0xFF);
    }
    
    /**
     * invMixColumns 메소드에서 사용하는 역연산 함수
     * @param a value 1
     * @param b value 2
     * @return Result
     * @see #invMixColumns(byte[][])
     */
    public static byte mul(int a, byte b) {
        int result = 0;
        int val = b & 0xff;
        
        for (int i = 0; i < 8; i++) {
            if ((a & (1 << i)) != 0) {
                result ^= xtime(val, i);
            }
        }
        
        return (byte) result;
    }
    
    /**
     * invMixColumns 메소드에서 사용하는 mul 함수의 보조 함수
     * @param val value 1
     * @param times value 2
     * @return Result
     * @see #invMixColumns(byte[][])
     * @see #mul(int, byte)
     */
    private static int xtime(int val, int times) {
        for (int i = 0; i < times; i++) {
            val = (val << 1);
            if ((val & 0x100) != 0) {
                val ^= 0x11b;
            }
        }
        return val & 0xff;
    }
    
    /**
     * Word 단위로 S-Box 연산을 수행하는 keySchedule 보조 함수
     * @param word Word Input
     * @return Result
     * @see Table#intSBox
     * @see #keySchedule(byte[], int, int, int)
     */
    private static int subWord(int word) {
        int result = 0;
        for (int i = 3; i >= 0; i--) {
            int bytePart = (word >>> (i * 8)) & 0xFF; // i번째 바이트 추출
            int row = (bytePart >>> 4) & 0x0F;        // 상위 4비트
            int col = bytePart & 0x0F;                // 하위 4비트
            int substituted = Table.intSBox[row][col];         // S-box에서 변환
            result = (result << 8) | substituted;     // 결과에 추가
        }
        return result;
    }
    
    /**
     * Word 단위로 1만큼 왼쪽으로 쉬프트하는 keySchedule 보조 함수
     * @param W Word Input
     * @return Result
     * @see #keySchedule(byte[], int, int, int)
     */
    private static int rotWord(int W) {
        return (W << 8) | ((W >>> 24) & 0xff);
    }
    
    /**
     * .txt 파일에서 16진수 값을 읽고 불러오는 메소드이다.
     * @param path file Path (absolute)
     * @return file Input
     * @throws IOException 파일 불러오기 실패 시 다음 오류 반환
     */
    public static byte[] readHexFromFile(String path) throws IOException {
        String hexString = Files.readString(Path.of(path)).replaceAll("\\s", "");
        if (hexString.length() % 2 != 0) throw new IllegalArgumentException("Hex 문자열 갯수가 짝수가 아닙니다.");
        return hexToBytes(hexString);
    }
    
    /**
     * 1차원 바이트 배열에서 2차원 State 형태로 변환해주는 메소드
     * @param arr 1차원 바이트 배열
     * @return 2차원 State 배열
     * @see <a href="https://csrc.nist.gov/pubs/fips/197/final">FIPS-197</a>
     */
    public static byte[][] arrayToState(byte[] arr) {
        if (arr.length != 16) throw new IllegalArgumentException("CAUTION: THIS FUNCTION IS ONLY FOR TRANSFORM TO STATE. But Your Length: "+arr.length);
        byte[][] res = new byte[4][4];
        res[0][0] = arr[0];
        res[1][0] = arr[1];
        res[2][0] = arr[2];
        res[3][0] = arr[3];
        
        res[0][1] = arr[4];
        res[1][1] = arr[5];
        res[2][1] = arr[6];
        res[3][1] = arr[7];
        
        res[0][2] = arr[8];
        res[1][2] = arr[9];
        res[2][2] = arr[10];
        res[3][2] = arr[11];
        
        res[0][3] = arr[12];
        res[1][3] = arr[13];
        res[2][3] = arr[14];
        res[3][3] = arr[15];
        
        return res;
    }
    
    /**
     * Pkcs7 패딩을 적용해주는 메소드이다.
     * @param val 입력값
     * @param blockSize 블록 사이즈(크기)
     * @return 패딩이 적용된 값 반환
     * @see #remPkcs7Padd(byte[])
     */
    public static byte[] pkcs7Padding(byte[] val, int blockSize) {
        int padLen = blockSize - (val.length % blockSize);
        if (padLen == 0) padLen = blockSize;
        byte[] padded = new byte[val.length + padLen];
        System.arraycopy(val, 0, padded, 0, val.length);
        for (int i = val.length; i < padded.length; i++) {
            padded[i] = (byte) padLen;
        }
        return padded;
    }
    
    /**
     * Pkcs7 패딩이 적용된 배열에서 패딩을 제거해주는 메소드이다.
     * @param val 입력값
     * @return 패딩이 제거된 배열 반환
     * @see #pkcs7Padding(byte[], int)
     */
    public static byte[] remPkcs7Padd(byte[] val) {
        int padLen = val[val.length - 1] & 0xff;
        if (padLen < 1 || padLen > 16) {
            throw new IllegalArgumentException("잘못된 패딩 길이입니다: " + padLen);
        }
        for (int i = 1; i <= padLen; i++) {
            if (val[val.length - i] != (byte) padLen) {
                throw new IllegalArgumentException("패딩이 유효하지 않습니다");
            }
        }
        byte[] unpadded = new byte[val.length - padLen];
        System.arraycopy(val, 0, unpadded, 0 , unpadded.length);
        return unpadded;
    }
    
    /**
     * 바이트 배열에서 16진수 문자열로 변환해주는 메소드
     * @param bytes 바이트 배열 입력
     * @return 16진수 문자열
     * @see #hexToBytes(String)
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    /**
     * 16진수 문자열에서 바이트 배열로 변환해주는 메소드
     * @param hex 16진수 문자열 입력
     * @return 바이트 배열 반환
     * @see #bytesToHex(byte[])
     */
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] result = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return result;
    }
    
    /**
     * 2차원 State 배열을 1차원 바이트 배열로 변환해주는 메소드
     * @param state State 입력
     * @return 1차원 바이트 배열
     * @see #arrayToState(byte[])
     */
    public static byte[] flattenState(byte[][] state) {
        byte[] flat = new byte[16];
        int index = 0;
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                flat[index++] = state[row][col];
            }
        }
        return flat;
    }
}
