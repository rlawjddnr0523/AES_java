import com.googlecode.lanterna.*;
import com.googlecode.lanterna.TextColor.ANSI;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.screen.*;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Gui {
    public static void main(String[] args) throws IOException {
        DefaultTerminalFactory terminalFactory = new DefaultTerminalFactory()
                .setInitialTerminalSize(new TerminalSize(38, 35));
        Screen screen = terminalFactory.createScreen();
        screen.startScreen();
        
        // GUI 구성
        WindowBasedTextGUI textGUI = new MultiWindowTextGUI(screen);
        BasicWindow window = new BasicWindow("AES_Java");
        Panel panel = new Panel();
        panel.setLayoutManager(new LinearLayout(Direction.VERTICAL));
        
        // 옵션 선택용 ComboBoxes
        ComboBox<String> modeBox = new ComboBox<>("암호화", "복호화");
        ComboBox<String> keyBox = new ComboBox<>("사용자 정의", "무작위");
        ComboBox<String> keySizeBox = new ComboBox<>("128", "192", "256");
        ComboBox<String> cipherModeBox = new ComboBox<>("ECB", "CBC");
        ComboBox<String> paddingBox = new ComboBox<>("NoPadding", "Pkcs7Padding");
        
//        panel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        
        Panel topPanel = new Panel();
        topPanel.setLayoutManager(new LinearLayout(Direction.VERTICAL));
        
        Panel Panel1 = new Panel();
        Panel1.addComponent(new Label("∙ 실행 선택:"));
        Panel1.addComponent(modeBox);
        
        Panel Panel2 = new Panel();
        Panel2.addComponent(new Label("∙ 비밀 키"));
        Panel2.addComponent(keyBox);
        Panel2.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        
        Panel Panel3 = new Panel();
        Panel3.addComponent(new Label("∙ 키 길이"));
        Panel3.addComponent(keySizeBox);
        
        Panel Panel4 = new Panel();
        Panel4.addComponent(new Label("∙ 모드"));
        Panel4.addComponent(cipherModeBox);
        
        Panel Panel5 = new Panel();
        Panel5.addComponent(new Label("∙ 패딩"));
        Panel5.addComponent(paddingBox);
        
        topPanel.addComponent(Panel1);
        topPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        topPanel.addComponent(Panel2);
        topPanel.addComponent(Panel3);
        topPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        topPanel.addComponent(Panel4);
        topPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        topPanel.addComponent(Panel5);
        topPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        panel.addComponent(topPanel);
        
        // 파일 경로 입력란
        panel.addComponent(new Label("∙ 입력 파일 경로"));
        TextBox inputFileBox = new TextBox().setValidationPattern(Pattern.compile(".*"))
                .setPreferredSize(new TerminalSize(30, 1));
        panel.addComponent(inputFileBox);
        
        panel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        
        panel.addComponent(new Label("∙ 출력 파일 경로"));
        TextBox outputFileBox = new TextBox().setValidationPattern(Pattern.compile(".*"))
                .setPreferredSize(new TerminalSize(30, 1));
        panel.addComponent(outputFileBox);
        
        panel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        
        Panel keyPathPanel = new Panel();
        Label keyPathLabel = new Label("∙ 키 파일 경로");
        TextBox keyFileBox = new TextBox().setValidationPattern(Pattern.compile(".*"))
                .setPreferredSize(new TerminalSize(30, 1));
        keyPathPanel.addComponent(keyPathLabel);
        keyPathPanel.addComponent(keyFileBox);
        panel.addComponent(keyPathPanel);
        
        Panel ivPanel = new Panel();
        Label ivLabel = new Label("∙ 초기화 벡터 파일 경로");
        TextBox ivFileBox = new TextBox()
                .setValidationPattern(Pattern.compile(".*"))
                .setPreferredSize(new TerminalSize(30, 1));
        ivPanel.addComponent(ivLabel);
        ivPanel.addComponent(ivFileBox);
        panel.addComponent(ivPanel);
        ivPanel.setVisible(false);
        keyPathPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        
        modeBox.addListener((sidx, prev, usrInt) -> {
            String selected = modeBox.getSelectedItem();
            Panel2.setVisible(!"복호화".equals(selected));
        });
        cipherModeBox.addListener((selectionIndex, previousSelection, changedByUserInteraction) -> {
            String selected = cipherModeBox.getSelectedItem();
            ivPanel.setVisible("CBC".equals(selected));
        });
        keyBox.addListener((selectionIndex, previousSelection, changedByUserInteraction) -> {
            String selected = keyBox.getSelectedItem();
            keyPathPanel.setVisible("사용자 정의".equals(selected));
        });
        
        // 실행 버튼
        panel.addComponent(new Button("Execute", () -> {
            int Nk, Nb, Nr;
            if (keySizeBox.getSelectedItem().equals("128")) { Nk = 4; Nb = 4; Nr = 10; }
            else if (keySizeBox.getSelectedItem().equals("192")) { Nk = 6; Nb = 4; Nr = 12; }
            else if (keySizeBox.getSelectedItem().equals("256")) { Nk = 8; Nb = 4; Nr = 14; }
            else throw new IllegalArgumentException("Error has been Occured in KeyBox");
            
            Path inputPath = Paths.get(inputFileBox.getText()).toAbsolutePath();
            Path outputPath = Paths.get(outputFileBox.getText()).toAbsolutePath();
            Path keyPath = Paths.get(keyFileBox.getText()).toAbsolutePath();
            
            if (modeBox.getSelectedItem().equals("암호화")) {
                byte[] plainFile, K;
                try {
                    plainFile = Functions.readHexFromFile(inputPath.toString());
                    if (keyBox.getSelectedItem().equals("무작위")) {
                        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                        keyGenerator.init(Integer.parseInt(keySizeBox.getSelectedItem()));
                        SecretKey secretKey = keyGenerator.generateKey();
                        byte[] rawKey = secretKey.getEncoded();
                        Files.writeString(Path.of("secure.txt"), Functions.bytesToHex(rawKey));
                        K = rawKey;
                        System.out.println(Functions.bytesToHex(K));
                    } else {
                        K = Functions.readHexFromFile(keyPath.toString());
                    }
                } catch (IOException e) {
                    throw new IllegalArgumentException(e.getMessage()+" file IO Failed");
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
                if (paddingBox.getSelectedItem().equals("NoPadding")) {
                    if ((plainFile.length & 16) != 0) {
                        throw new IllegalArgumentException("NoPadding Option requires 128bit PlainText");
                    }
                }
                if (paddingBox.getSelectedItem().equals("Pkcs7Padding")) {
                    plainFile = Functions.pkcs7Padding(plainFile, 16);
                }
                int blockCnt = plainFile.length / 16; // 블록 갯수 지정
                List<byte[][]> blocks = new ArrayList<>(); // 블록들을 저장할 리스트
                StringBuilder res = new StringBuilder(); // 결과
                // 블록 갯수 만큼 실행할 반복문.
                for (int i = 0; i < blockCnt; i++) {
                    byte[] block = Arrays.copyOfRange(plainFile, i * 16, (i + 1) * 16);
                    byte[][] state = Functions.arrayToState(block); // State 방식으로 바꿔서 2차원 배열에 저장
                    blocks.add(state); // 리스트에 블록 저장
                }
                if (cipherModeBox.getSelectedItem().equals("ECB")) {
                    for (int i = 0; i < blockCnt; i++) {
                        byte[][] P = blocks.get(i);                     // 평문 블록 State
                        Functions.Encrypt(P, K, Nr, Nk, Nb);            // 암호화 수행
                        byte[] cipherBlock = Functions.flattenState(P); // 암호문 추출
                        res.append(Functions.bytesToHex(cipherBlock));  // 결과 누적
                    }
                    // 암호화 결과를 저장할 파일에 결과 삽입.
                    try {
                            Files.writeString(outputPath, res);
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    // 암호화 성공 메세지 출력.
//                    panel.addComponent(new Label("AES/ECB 암호화 완료."));
                    System.out.println("AES/ECB 암호화 완료. \n저장 경로: " + outputPath);
                }
                else if (cipherModeBox.getSelectedItem().equals("CBC")) {
                    byte[] IV;
                    try {
                        IV = Functions.readHexFromFile(ivFileBox.toString());
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
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
                    try {
                        Files.writeString(outputPath, res);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    // 암호화 성공 메세지 출력
                    System.out.println("AES/CBC 암호화 성공");
                }
                else throw new IllegalArgumentException("Error has been Occured in CipherModeBox");
            }
            else if (modeBox.getSelectedItem().equals("복호화")) {
                byte[] cipher;
                byte[] K;
                try {
                    cipher = Functions.readHexFromFile(inputPath.toString());
                    K = Functions.readHexFromFile(keyPath.toString());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                if (paddingBox.getSelectedItem().equals("NoPadding")) {
                    if (cipher.length % 16 != 0) {
                        throw new IllegalArgumentException("NoPadding Option requires multiplier of 128 on PlainText");
                    }
                }
                int blockCnt = cipher.length / 16;
                List<byte[][]> blocks = new ArrayList<>();
                StringBuilder res = new StringBuilder();
                for (int i = 0; i < blockCnt; i++) {
                    byte[] block = Arrays.copyOfRange(cipher, i * 16, (i + 1) * 16);
                    byte[][] state = Functions.arrayToState(block);
                    blocks.add(state);
                }
                if (cipherModeBox.getSelectedItem().equals("ECB")) {
                    for (int i = 0; i < blockCnt; i++) {
                        byte[][] C = blocks.get(i);
                        Functions.Decrypt(C, K, Nr, Nk, Nb);
                        byte[] flat = Functions.flattenState(C);
                        if (i == blockCnt - 1 && paddingBox.getSelectedItem().equals("Pkcs7Padding")) {
                            flat = Functions.remPkcs7Padd(flat);
                        }
                        res.append(Functions.bytesToHex(flat));
                    }
                    try {
                        Files.writeString(outputPath, res);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    System.out.println("복호화 성공");
                }
                else if (cipherModeBox.getSelectedItem().equals("CBC")) {
                    byte[] IV;
                    Path ivPath = Paths.get(ivFileBox.toString()).toAbsolutePath();
                    try {
                        IV = Functions.readHexFromFile(ivPath.toString());
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    for (int i = 0; i < blockCnt; i++) {
                        byte[][] C = blocks.get(i);
                        byte[] tmp = Functions.flattenState(C);
                        Functions.Decrypt(C, K, Nr, Nk, Nb);
                        byte[] flat = Functions.flattenState(C);
                        for (int j = 0; j < flat.length; j++) {
                            flat[j] ^= IV[j];
                        }
                        IV = tmp;
                        if (i == blockCnt - 1 && paddingBox.getSelectedItem().equals("Pkcs7Padding")) {
                            flat = Functions.remPkcs7Padd(flat);
                        }
                        res.append(Functions.bytesToHex(flat));
                    }
                    try {
                        Files.writeString(outputPath, res);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    System.out.println("AES/CBC 복호화 성공");
                } else throw new IllegalArgumentException("Error has been Occured in CipherModeBox");
            }
            else {
                throw new IllegalArgumentException("오류가 발생했습니다. modeBox");
            }
        }));
        
        panel.addComponent(new Button("Exit", window::close));
        
        window.setComponent(panel);
        textGUI.addWindowAndWait(window);
        screen.stopScreen();
    }
}
