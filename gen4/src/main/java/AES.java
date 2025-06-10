import java.util.*;
import java.nio.file.*;
import org.apache.commons.cli.*;
import java.io.IOException;

public class AES {
    public static void main(String[] args) throws IOException, org.apache.commons.cli.ParseException {
        
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
            
            // 키 길이가 선택한 키 길이와 일치 하지 않을 경우 반환.
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
