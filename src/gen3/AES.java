package gen3;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.apache.commons.cli.*;

/**
 * 메인 로직이 있는 클래스
 */
class AES {
    public static void main(String[] args) throws IOException, ParseException {
        
        // CLI 옵션 추가 코드 -- apache commons cli
        Options options = new Options();

        // 암호화 or 복호화 선택
        options.addOption("e", "encrypt", false, "Encrypt the input");
        options.addOption("d", "decrypt", false, "Decrypt the input");
        
        // 키 길이 선택
        options.addOption(Option.builder("k").longOpt("keysize").hasArg().argName("128|192|256(bit)")
                .desc("Set AES Key size in bits: 128, 192 or 256").required().build());
        
        // 모드 선택
        options.addOption(Option.builder("m").longOpt("mode").hasArg().argName("ECB|CBC")
                .desc("Set AES Mode").required().build());
        
        // 패딩 방식 선택
        options.addOption(Option.builder("p").longOpt("padding").hasArg()
                .desc("Padding Option Select. NoPadding, PKCS7Padding").required().build());
        
        // 암/복호문 파일 경로 지정 (절대 경로)
        options.addOption(Option.builder("i").longOpt("infile").hasArg().argName("inputFilePath")
                .desc("Set Input file path").required().build());
        
        // 암/복호화 결과 저장 *파일* 경로 지정 (절대 경로)
        options.addOption(Option.builder("o").longOpt("outfile").hasArg().argName("outputPath")
                .desc("Set Output file path").required().build());
        
        // 암호 키 파일 경로 지정 (절대 경로)
        options.addOption(Option.builder("s").longOpt("keypath").hasArg().argName("keyFilePath")
                .desc("Set Key file path").required().build());
        
        // 초기화 벡터(CBC 모드 사용 시 지정) 파일 경로 지정 (절대 경로)
        options.addOption(Option.builder("iv").longOpt("initialvector").hasArg().argName("initialVector")
                .desc("Set IV Path(only CBC)").build());
        
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);
        
        int Nk, Nb, Nr;
        int keySize = Integer.parseInt(cmd.getOptionValue("keysize"));
        String mode = cmd.getOptionValue("mode").toLowerCase();
        String padding = cmd.getOptionValue("padding").toLowerCase();
        String iPath = Paths.get(cmd.getOptionValue("infile")).toAbsolutePath().toString();
        String oPath = Paths.get(cmd.getOptionValue("outfile")).toAbsolutePath().toString();
        String keyPath = Paths.get(cmd.getOptionValue("keypath")).toAbsolutePath().toString();
        String ivPath = Paths.get(cmd.getOptionValue("initialvector")).toAbsolutePath().toString();
        // 사실 이거 다 설명하려고 했는데 진짜 설명하다간 ㅈㄴ 지루해질것 같아서는 아니고 내가 ㅈㄴ 귀찬핟. 바주세요 ㅎㅎ
        
        // 키 길이 선택에 따라서 Nk, Nb, Nr 값 지정
        try {
            if (keySize == 128) { Nk = 4; Nb = 4; Nr = 10; }                                        // 128비트
            else if (keySize == 192) { Nk = 6; Nb = 4; Nr = 12; }                                   // 192비트
            else if (keySize == 256) { Nk = 8; Nb = 4; Nr = 14; }                                   // 256비트
            else throw new IllegalArgumentException("Invalid key size. Use 128, 192 or 256");       // 그 무엇도 아니면 반환
        }
        // 입력 인식도 못 하면 돌아가 이새갸 ㅋㅋ
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("Key size must be an integer: 128, 192 or 256");
        }
        
        // 암호화(--e or --encrypt) 옵션 선택 시 실행 할 구문
        if (cmd.hasOption("encrypt")) {
            
            byte[] plainFile = Functions.readHexFromFile(iPath);        // 입력 파일에서 hex값 가져오고 byte로 저장.
            byte[] K = Functions.readHexFromFile(keyPath);              // 암호키 파일에서 hex값 가져오고 byte로 저장.
            byte[] IV = Functions.readHexFromFile(ivPath);              // 초기화 벡터 파일에서 hex값 가져오고 byte로 저장.
            
            // 키 길이가 평문길이와 일치 하지 않을 경우 반환.
            if (keySize / 8 != K.length) {
                throw new IllegalArgumentException(
                        "Key size error. Please check your Key File.\n"
                                + "Your Key size: " + K.length * 8 + "bit. but Your keyLength Selection: " + keySize + "bit. Please check your Key File.\n");
            }
            
            // ECB 모드 선택 시 동작하는 구문.
            if (mode.equals("ecb")) {
                
                // 평문의 길이가 128비트를 넘지 않을 경우 반환.
                if (plainFile.length*8 != 128) throw new IllegalArgumentException("Plain File must be 128 bits. But your file: "+plainFile.length*8+"bits.");
                
                // 평문을 2차원 바이트 배열 State로 변환.
                byte[][] P = Functions.arrayToState(plainFile);
                
                // 암호화 시행
                Functions.Encrypt(P,K, Nr, Nk, Nb);
                
                // 지정된 경로에 있는 파일에 결과 저장.
                Files.writeString(Path.of(oPath), Functions.bytesToHex(Functions.flattenState(P)));
                
                // 암호화 성공 메세지 출력.
                System.out.println("AES/ECB 암호화 완료. \n저장 경로: "+oPath);
            }
            
            // CBC 모드 선택 시 실행하는 구문
            else if (mode.equals("cbc")) {
                
                // 패딩 없이 암호화를 진행하는 경우엔 128의 배수가 되는 평문 길이를 가져야함.
                if (padding.equals("nopadding")) {
                    if (plainFile.length * 8 % 128 != 0) {
                        throw new IllegalArgumentException("NoPadding option must be a multiple of 128. else, select other padding option.");
                    }
                }
                // Pkcs7 패딩을 선택했을때 실행하는 구문.
                else if (padding.equals("pkcs7padding")) {
                    plainFile = Functions.pkcs7Padding(plainFile, 16);
                }
                // 그 무엇도 선택하지 않았다면 오류나 먹으쇼.
                else {
                    throw new IllegalArgumentException("Padding Option Must be Selected"); // 무조건 패딩 옵션을 선택하셈.!.!
                }
                
                // 본격적인 암호화 시작
                int blockCnt = plainFile.length / 16; // 블록 갯수 지정
                List<byte[][]> blocks = new ArrayList<>(); // 블록들을 저장할 리스트
                
                // 블록 갯수 만큼 실행할 반복문.
                for (int i = 0; i < blockCnt; i++) {
                    byte[] block = Arrays.copyOfRange(plainFile, i * 16, (i + 1) * 16);
                    byte[][] state = Functions.arrayToState(block); // State 방식으로 바꿔서 2차원 배열에 저장
                    blocks.add(state); // 리스트에 블록 저장
                }
                
                StringBuilder res = new StringBuilder(); // 결괏값을 저장할 문자열
                
                // 블록 갯수만큼 실행할 반복문.
                for (int i = 0; i < blockCnt; i++) {
                    byte[][] P = blocks.get(i);                     // 평문 블록 State
                    
                    byte[] flat = Functions.flattenState(P);   // State → 바이트 배열
                    for (int j = 0; j < 16; j++) {
                        flat[j] ^= IV[j];                           // CBC: 평문 ⊕ IV
                    }
                    
                    byte[][] xorState = Functions.arrayToState(flat); // 다시 State로 복원
                    Functions.Encrypt(xorState, K, Nr, Nk, Nb);      // 암호화 수행
                    
                    byte[] cipherBlock = Functions.flattenState(xorState); // 암호문 추출
                    IV = cipherBlock; // 다음 블록을 위한 IV 업데이트
                    
                    res.append(Functions.bytesToHex(cipherBlock)); // 결과 누적
                }
                
                // 암호화 결과를 저장할 파일에 결과 삽입.
                Files.writeString(Path.of(oPath), res);
                
                // 암호화 성공 메세지 출력
                System.out.printf("AES/%s/%s %d비트 암호화 완료.\n저장 경로: %s", mode.toUpperCase(), padding.toUpperCase(), keySize, oPath);
            }
            
            // ECB나 CBC중 아무것도 선택하지 않으면 이 에러 보여줄거임 ㅅㄱ.
            else {
                throw new IllegalArgumentException("Encrypt mode must be Selected."); // 모드 선택하라고!!!!!!!!!!
            }
        }
        
        // 복호화(--d or --decrypt) 옵션 선택 시 실행 할 구문
        else if (cmd.hasOption("decrypt")) {
            byte[] plainFile = Functions.readHexFromFile(iPath); // 암호문 파일 가져오기
            byte[] K = Functions.readHexFromFile(keyPath); // 암호키 파일 가져오기
            byte[] IV = Functions.readHexFromFile(ivPath); // 초기화 벡터 값 가져오기
            
            // 님이 선택한 키 길이하고 입력된 키 길이하고 다르면 반환때리는 코드                            EZ 77r 77r
            if (keySize / 8 != K.length) {
                throw new IllegalArgumentException(
                        "Key size error. Please check your Key File.\nYour Key size: " + K.length * 8
                                + "bit. but Your keyLength Selection: " + keySize
                                + "bit. Please check your Key File.\n");
            }
            
            // 이씨발모드 선택시 실행할 조건문.이죠?
            if (mode.equals("ecb")) {
                
                // 암호문 파일 길이가 128비트가 아니면 반환 쌔릴거임.
                if (plainFile.length * 8 != 128) throw new IllegalArgumentException("Plain File must be 128 bits.");
                
                // 한번 싸악 걸러줬으니? State로 변환해주기
                byte[][] P = Functions.arrayToState(plainFile);
                
                // 복호화 수행.....하는중.....
                Functions.Decrypt(P, K, Nr, Nk, Nb);
                
                // 복호화 끝나면? 바로다가 파일에 값 집어넣고 퇴근.
                Files.writeString(Path.of(oPath), Functions.bytesToHex(Functions.flattenState(P)));
                
                // 유후~ 복호화 성공이다~
                System.out.println("AES/ECB 복호화 완료. \n저장 경로: "+oPath);
            }
            
            // 씨발씨모드 선택시 실행할 조건문임.
            else if (mode.equals("cbc")) {
                
                // 나 솔직히 이 코드에서 포기할까 생각했었다.
                // 블록 길이 지정해주고요~
                int blockCnt = plainFile.length / 16;
                
                // 결과 저장할 리스트 하나 때려박아주시고~
                List<byte[][]> blocks = new ArrayList<>();
                
                // 발사!
                for (int i = 0; i < blockCnt; i++) {
                    byte[] block = Arrays.copyOfRange(plainFile, i * 16, (i + 1) * 16);
                    byte[][] state = Functions.arrayToState(block);
                    blocks.add(state); // 블록 만들기 참 쉽죠?
                }
                
                // 결괏값 저장할 문자열도 하나 뚝딱해주고~
                StringBuilder res = new StringBuilder();
                
                // 발ㅅ사1ㅏ
                for (int i = 0; i < blockCnt; i++) {
                    
                    // 복호화할 블록 불러와주고~
                    byte[][] C = blocks.get(i);
                    
                    // 마지막에 IV랑 XOR 해줘야하니까 일단 저장해놓고~
                    byte[] tmp = Functions.flattenState(C);
                    
                    // 복호화 때려주면?
                    Functions.Decrypt(C, K, Nr, Nk, Nb);
                    
                    // 짜잔~ 복호화 성공~ 인것 같지만.. 초기화 벡터랑 씨름 한번 더 해주고..
                    byte[] flat = Functions.flattenState(C);
                    for (int j = 0; j < flat.length; j++) {
                        flat[j] ^= IV[j]; // 초기화 벡터랑 XOR 연산
                    }
                    IV = tmp; // 이전 블록 암호문이 이제 초기화 벡터로 변신! (0번째 블록에는 이전 블록 암호문 아님)
                    
                    // 패딩 제거는 마지막 블록에서만 수행하고 싶진 않았는데, 능지한계로인해서 그렇게햇음. 어ㅉ러거임?
                    if (i == blockCnt - 1 && padding.equals("pkcs7padding")) {
                        flat = Functions.remPkcs7Padd(flat); // 패딩 제거해주시고~
                    }
                    
                    // 우와 고지가 보인다~
                    res.append(Functions.bytesToHex(flat));
                }
                
                // 자~ 이제 복호화 끝났으면? 파일에 집어넣어줘야겠죠~
                Files.writeString(Path.of(oPath), res);
                
                // 복호화 성공!!!!!!!
                System.out.printf("AES/%s/%s %d비트 복호화 완료.\n저장 경로: %s", mode.toUpperCase(), padding.toUpperCase(), keySize, oPath);
            }
            
            // 그 무엇도 아니면 반환 때리는건 이제 익숙하잖아 ㅋㅋ
            else {
                throw new IllegalArgumentException("Decrypt Mode Must be Selected."); // 씨발롬아 모드 선택하라고!!!!!!!!!
            }
        }
        
        // 암호화나 복호화 둘중 어느것도 선택하지 않으면 이 코드 맛보게 될 것이야.
        else {
            throw new IllegalArgumentException(
                    "You must specify --encrypt or --decrypt options."); // 씨발아 암호화할거임 복호화할거임???? 선택하셈. 10초드림.
        }
    }
}

/**
 * 암, 복호화에 사용하는 메소드를 모아놓은 클래스
 */
class Functions {
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
     * 라운드 키를 따로 추출하는 함수. 인데 안 쓰긴 함.
     * @param W Values After KeySchedule()
     * @param round Round Value
     * @param Nb Fixed value 4
     * @return RoundKey [ Nr + 2 ]
     * @deprecated 사용되지 않는 메소드입니다. {@link #keySchedule(byte[], int, int, int)} 에서 파생 됨.
     */
    public static int[] getRoundKey(int[] W, int round, int Nb) {
        int[] roundKey = new int[Nb];  // Nb == 4
        int start = round * Nb;
        for (int i = 0; i < Nb; i++) {
            roundKey[i] = W[start + i];
        }
        return roundKey;
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

/**
 * 연산에 사용하는 테이블들을 이 클래스에 정리해놓았음
 */
class Table {
    
    /**
     * subBytes 함수에서 사용함.
     * @see Functions#subBytes(byte[][])
     */
    public static final byte[][] sBox = new byte[][] {
    //           0            1          2           3           4           5           6           7           8           9           a           b           c           d           e           f
    /* 0 */{(byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5, (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76},
    /* 1 */{(byte)0xca, (byte)0x82, (byte)0xc9, (byte)0x7d, (byte)0xfa, (byte)0x59, (byte)0x47, (byte)0xf0, (byte)0xad, (byte)0xd4, (byte)0xa2, (byte)0xaf, (byte)0x9c, (byte)0xa4, (byte)0x72, (byte)0xc0},
    /* 2 */{(byte)0xb7, (byte)0xfd, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3f, (byte)0xf7, (byte)0xcc, (byte)0x34, (byte)0xa5, (byte)0xe5, (byte)0xf1, (byte)0x71, (byte)0xd8, (byte)0x31, (byte)0x15},
    /* 3 */{(byte)0x04, (byte)0xc7, (byte)0x23, (byte)0xc3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9a, (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xe2, (byte)0xeb, (byte)0x27, (byte)0xb2, (byte)0x75},
    /* 4 */{(byte)0x09, (byte)0x83, (byte)0x2c, (byte)0x1a, (byte)0x1b, (byte)0x6e, (byte)0x5a, (byte)0xa0, (byte)0x52, (byte)0x3b, (byte)0xd6, (byte)0xb3, (byte)0x29, (byte)0xe3, (byte)0x2f, (byte)0x84},
    /* 5 */{(byte)0x53, (byte)0xd1, (byte)0x00, (byte)0xed, (byte)0x20, (byte)0xfc, (byte)0xb1, (byte)0x5b, (byte)0x6a, (byte)0xcb, (byte)0xbe, (byte)0x39, (byte)0x4a, (byte)0x4c, (byte)0x58, (byte)0xcf},
    /* 6 */{(byte)0xd0, (byte)0xef, (byte)0xaa, (byte)0xfb, (byte)0x43, (byte)0x4d, (byte)0x33, (byte)0x85, (byte)0x45, (byte)0xf9, (byte)0x02, (byte)0x7f, (byte)0x50, (byte)0x3c, (byte)0x9f, (byte)0xa8},
    /* 7 */{(byte)0x51, (byte)0xa3, (byte)0x40, (byte)0x8f, (byte)0x92, (byte)0x9d, (byte)0x38, (byte)0xf5, (byte)0xbc, (byte)0xb6, (byte)0xda, (byte)0x21, (byte)0x10, (byte)0xff, (byte)0xf3, (byte)0xd2},
    /* 8 */{(byte)0xcd, (byte)0x0c, (byte)0x13, (byte)0xec, (byte)0x5f, (byte)0x97, (byte)0x44, (byte)0x17, (byte)0xc4, (byte)0xa7, (byte)0x7e, (byte)0x3d, (byte)0x64, (byte)0x5d, (byte)0x19, (byte)0x73},
    /* 9 */{(byte)0x60, (byte)0x81, (byte)0x4f, (byte)0xdc, (byte)0x22, (byte)0x2a, (byte)0x90, (byte)0x88, (byte)0x46, (byte)0xee, (byte)0xb8, (byte)0x14, (byte)0xde, (byte)0x5e, (byte)0x0b, (byte)0xdb},
    /* a */{(byte)0xe0, (byte)0x32, (byte)0x3a, (byte)0x0a, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5c, (byte)0xc2, (byte)0xd3, (byte)0xac, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xe4, (byte)0x79},
    /* b */{(byte)0xe7, (byte)0xc8, (byte)0x37, (byte)0x6d, (byte)0x8d, (byte)0xd5, (byte)0x4e, (byte)0xa9, (byte)0x6c, (byte)0x56, (byte)0xf4, (byte)0xea, (byte)0x65, (byte)0x7a, (byte)0xae, (byte)0x08},
    /* c */{(byte)0xba, (byte)0x78, (byte)0x25, (byte)0x2e, (byte)0x1c, (byte)0xa6, (byte)0xb4, (byte)0xc6, (byte)0xe8, (byte)0xdd, (byte)0x74, (byte)0x1f, (byte)0x4b, (byte)0xbd, (byte)0x8b, (byte)0x8a},
    /* d */{(byte)0x70, (byte)0x3e, (byte)0xb5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xf6, (byte)0x0e, (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xb9, (byte)0x86, (byte)0xc1, (byte)0x1d, (byte)0x9e},
    /* e */{(byte)0xe1, (byte)0xf8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xd9, (byte)0x8e, (byte)0x94, (byte)0x9b, (byte)0x1e, (byte)0x87, (byte)0xe9, (byte)0xce, (byte)0x55, (byte)0x28, (byte)0xdf},
    /* f */{(byte)0x8c, (byte)0xa1, (byte)0x89, (byte)0x0d, (byte)0xbf, (byte)0xe6, (byte)0x42, (byte)0x68, (byte)0x41, (byte)0x99, (byte)0x2d, (byte)0x0f, (byte)0xb0, (byte)0x54, (byte)0xbb, (byte)0x16}
    };
    
    /**
     * subWord 함수에서 사용함.
     * @see Functions#subWord(int)
     */
    public static final int[][] intSBox = new int[][] {
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };
    
    /**
     * invSubBytes 함수에서 복호화시 사용하는 테이블.
     * @see Functions#invSubBytes(byte[][])
     */
    public static final byte[][] invSbox = new byte[][] {
    //           0           1           2           3           4           5           6           7           8           9           a           b           c           d           e           f
    /* 0 */{(byte)0x52, (byte)0x09, (byte)0x6a, (byte)0xd5, (byte)0x30, (byte)0x36, (byte)0xa5, (byte)0x38, (byte)0xbf, (byte)0x40, (byte)0xa3, (byte)0x9e, (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb},
    /* 1 */{(byte)0x7c, (byte)0xe3, (byte)0x39, (byte)0x82, (byte)0x9b, (byte)0x2f, (byte)0xff, (byte)0x87, (byte)0x34, (byte)0x8e, (byte)0x43, (byte)0x44, (byte)0xc4, (byte)0xde, (byte)0xe9, (byte)0xcb},
    /* 2 */{(byte)0x54, (byte)0x7b, (byte)0x94, (byte)0x32, (byte)0xa6, (byte)0xc2, (byte)0x23, (byte)0x3d, (byte)0xee, (byte)0x4c, (byte)0x95, (byte)0x0b, (byte)0x42, (byte)0xfa, (byte)0xc3, (byte)0x4e},
    /* 3 */{(byte)0x08, (byte)0x2e, (byte)0xa1, (byte)0x66, (byte)0x28, (byte)0xd9, (byte)0x24, (byte)0xb2, (byte)0x76, (byte)0x5b, (byte)0xa2, (byte)0x49, (byte)0x6d, (byte)0x8b, (byte)0xd1, (byte)0x25},
    /* 4 */{(byte)0x72, (byte)0xf8, (byte)0xf6, (byte)0x64, (byte)0x86, (byte)0x68, (byte)0x98, (byte)0x16, (byte)0xd4, (byte)0xa4, (byte)0x5c, (byte)0xcc, (byte)0x5d, (byte)0x65, (byte)0xb6, (byte)0x92},
    /* 5 */{(byte)0x6c, (byte)0x70, (byte)0x48, (byte)0x50, (byte)0xfd, (byte)0xed, (byte)0xb9, (byte)0xda, (byte)0x5e, (byte)0x15, (byte)0x46, (byte)0x57, (byte)0xa7, (byte)0x8d, (byte)0x9d, (byte)0x84},
    /* 6 */{(byte)0x90, (byte)0xd8, (byte)0xab, (byte)0x00, (byte)0x8c, (byte)0xbc, (byte)0xd3, (byte)0x0a, (byte)0xf7, (byte)0xe4, (byte)0x58, (byte)0x05, (byte)0xb8, (byte)0xb3, (byte)0x45, (byte)0x06},
    /* 7 */{(byte)0xd0, (byte)0x2c, (byte)0x1e, (byte)0x8f, (byte)0xca, (byte)0x3f, (byte)0x0f, (byte)0x02, (byte)0xc1, (byte)0xaf, (byte)0xbd, (byte)0x03, (byte)0x01, (byte)0x13, (byte)0x8a, (byte)0x6b},
    /* 8 */{(byte)0x3a, (byte)0x91, (byte)0x11, (byte)0x41, (byte)0x4f, (byte)0x67, (byte)0xdc, (byte)0xea, (byte)0x97, (byte)0xf2, (byte)0xcf, (byte)0xce, (byte)0xf0, (byte)0xb4, (byte)0xe6, (byte)0x73},
    /* 9 */{(byte)0x96, (byte)0xac, (byte)0x74, (byte)0x22, (byte)0xe7, (byte)0xad, (byte)0x35, (byte)0x85, (byte)0xe2, (byte)0xf9, (byte)0x37, (byte)0xe8, (byte)0x1c, (byte)0x75, (byte)0xdf, (byte)0x6e},
    /* a */{(byte)0x47, (byte)0xf1, (byte)0x1a, (byte)0x71, (byte)0x1d, (byte)0x29, (byte)0xc5, (byte)0x89, (byte)0x6f, (byte)0xb7, (byte)0x62, (byte)0x0e, (byte)0xaa, (byte)0x18, (byte)0xbe, (byte)0x1b},
    /* b */{(byte)0xfc, (byte)0x56, (byte)0x3e, (byte)0x4b, (byte)0xc6, (byte)0xd2, (byte)0x79, (byte)0x20, (byte)0x9a, (byte)0xdb, (byte)0xc0, (byte)0xfe, (byte)0x78, (byte)0xcd, (byte)0x5a, (byte)0xf4},
    /* c */{(byte)0x1f, (byte)0xdd, (byte)0xa8, (byte)0x33, (byte)0x88, (byte)0x07, (byte)0xc7, (byte)0x31, (byte)0xb1, (byte)0x12, (byte)0x10, (byte)0x59, (byte)0x27, (byte)0x80, (byte)0xec, (byte)0x5f},
    /* d */{(byte)0x60, (byte)0x51, (byte)0x7f, (byte)0xa9, (byte)0x19, (byte)0xb5, (byte)0x4a, (byte)0x0d, (byte)0x2d, (byte)0xe5, (byte)0x7a, (byte)0x9f, (byte)0x93, (byte)0xc9, (byte)0x9c, (byte)0xef},
    /* e */{(byte)0xa0, (byte)0xe0, (byte)0x3b, (byte)0x4d, (byte)0xae, (byte)0x2a, (byte)0xf5, (byte)0xb0, (byte)0xc8, (byte)0xeb, (byte)0xbb, (byte)0x3c, (byte)0x83, (byte)0x53, (byte)0x99, (byte)0x61},
    /* f */{(byte)0x17, (byte)0x2b, (byte)0x04, (byte)0x7e, (byte)0xba, (byte)0x77, (byte)0xd6, (byte)0x26, (byte)0xe1, (byte)0x69, (byte)0x14, (byte)0x63, (byte)0x55, (byte)0x21, (byte)0x0c, (byte)0x7d},
    };
    
    /**
     * 원래는 복호화시에 {@link Functions#invSubBytes(byte[][])} 에서 사용하려고 했지만, 로직이 많이 망가져서 위 {@link #invSbox} 를 사용함
     * @deprecated 사용되지 않음.
     * @see Functions#invSubBytes(byte[][])
     * @see #invSbox
     */
    public static final int[][] intInvSbox = new int[][] {
        {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
        {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
        {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
        {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
        {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
        {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
        {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
        {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
        {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
        {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
        {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
        {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
        {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
        {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
        {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
        {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };
    
    /**
     * keySchedule에서 사용하는 라운드 상수(Constant)
     * @see Functions#keySchedule(byte[], int, int, int)
     */
    public static final int[] RCon = {
            0x00,
            0x01, 0x02, 0x04, 0x08,
            0x10, 0x20, 0x40, 0x80,
            0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d
    };
    
    /**
     * mixColumns에 GF(2^8) 연산에서 사용하려했던 유한체 연산테이블이지만, 로직이랑 맞지 않아서 사용하지 않는 테이블
     * @see Functions#mixColumns(byte[][])
     * @see Functions#gfMul(int, byte)
     * @deprecated 로직이랑 부합되지 않음
     */
    public static final int[] mixColTable = {
        0x02, 0x03, 0x01, 0x01,
        0x01, 0x02, 0x03, 0x01,
        0x01, 0x01, 0x02, 0x03,
        0x03, 0x01, 0x01, 0x02
    };
}
