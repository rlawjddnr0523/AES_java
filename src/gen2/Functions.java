package gen2;

public class Functions {
    
    public static byte[][] subBytes(byte[][] state, boolean debug){
        byte[][] res = new byte[4][4];
        
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                int val = state[row][col] & 0xFF;
                int high = (val >> 4) & 0x0F;
                int low = val & 0x0F;
                res[row][col] = sbox[high][low];
            }
        }
        if (debug) {
            System.out.println("s_box: \n"+byteMatrixToHex(res));
        }
        return res;
    }
    
    public static byte[][] shiftRows(byte[][] state, boolean debug){
        byte[][] res = new byte[4][4];
        
        res[0][0] = state[0][0];
        res[0][1] = state[0][1];
        res[0][2] = state[0][2];
        res[0][3] = state[0][3];
        
        res[1][0] = state[1][1];
        res[1][1] = state[1][2];
        res[1][2] = state[1][3];
        res[1][3] = state[1][0];
        
        res[2][0] = state[2][2];
        res[2][1] = state[2][3];
        res[2][2] = state[2][0];
        res[2][3] = state[2][1];
        
        res[3][0] = state[3][3];
        res[3][1] = state[3][0];
        res[3][2] = state[3][1];
        res[3][3] = state[3][2];
        
        if (debug) {
            System.out.println("s_row: \n"+byteMatrixToHex(res));
        }
        
        return res;
    }
    
    public static byte[][] mixColumns(byte[][] state, boolean debug){
        byte[][] res = new byte[4][4];
        for (int c = 0; c < 4; c++) {
            res[0][c] = (byte) (gmul(0x02, state[0][c]) ^ gmul(0x03, state[1][c]) ^ state[2][c] ^ state[3][c]);
            res[1][c] = (byte) (state[0][c] ^ gmul(0x02, state[1][c]) ^ gmul(0x03, state[2][c]) ^ state[3][c]);
            res[2][c] = (byte) (state[0][c] ^ state[1][c] ^ gmul(0x02, state[2][c]) ^ gmul(0x03, state[3][c]));
            res[3][c] = (byte) (gmul(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ gmul(0x02, state[3][c]));
        }
        
        if (debug) {
            System.out.println("m_col: \n"+byteMatrixToHex(res));
        }
        
        return res;
    }
    
    public static byte[][] invSubBytes(byte[][] state, boolean debug){
        byte[][] res = new byte[4][4];
        
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                int val = state[row][col] & 0xFF;
                int high = (val >> 4) & 0x0F;
                int low = val & 0x0F;
                res[row][col] = invSbox[high][low];
            }
        }
        if (debug) {
            System.out.println("is_box: \n"+byteMatrixToHex(res));
        }
        return res;
    }
    
    public static byte[][] invShiftRows(byte[][] state, boolean debug){
        byte[][] res = new byte[4][4];
        
        // row 0 - no shift
        res[0][0] = state[0][0];
        res[0][1] = state[0][1];
        res[0][2] = state[0][2];
        res[0][3] = state[0][3];
        
        // row 1 - shift right by 1
        res[1][0] = state[1][3];
        res[1][1] = state[1][0];
        res[1][2] = state[1][1];
        res[1][3] = state[1][2];
        
        // row 2 - shift right by 2
        res[2][0] = state[2][2];
        res[2][1] = state[2][3];
        res[2][2] = state[2][0];
        res[2][3] = state[2][1];
        
        // row 3 - shift right by 3
        res[3][0] = state[3][1];
        res[3][1] = state[3][2];
        res[3][2] = state[3][3];
        res[3][3] = state[3][0];
        
        if (debug) {
            System.out.println("is_row: \n" + byteMatrixToHex(res));
        }
        
        return res;
    }
    
    public static byte[][] invMixColumns(byte[][] state, boolean debug) {
        byte[][] res = new byte[4][4];
        
        for (int c = 0; c < 4; c++) {
            byte s0 = state[0][c];
            byte s1 = state[1][c];
            byte s2 = state[2][c];
            byte s3 = state[3][c];
            
            res[0][c] = (byte) (mul(0x0e, s0) ^ mul(0x0b, s1) ^ mul(0x0d, s2) ^ mul(0x09, s3));
            res[1][c] = (byte) (mul(0x09, s0) ^ mul(0x0e, s1) ^ mul(0x0b, s2) ^ mul(0x0d, s3));
            res[2][c] = (byte) (mul(0x0d, s0) ^ mul(0x09, s1) ^ mul(0x0e, s2) ^ mul(0x0b, s3));
            res[3][c] = (byte) (mul(0x0b, s0) ^ mul(0x0d, s1) ^ mul(0x09, s2) ^ mul(0x0e, s3));
        }
        
        if (debug) {
            System.out.println("im_col: \n"+byteMatrixToHex(res));
        }
        
        return res;
    }
    
    public static byte[][] addRoundKey(byte[][] state, byte[][] key, int round, boolean debug){
        int Nb = 4;
        int l = round * Nb;
        
        byte[][] res = new byte[4][4];
        
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                res[row][col] = (byte) (state[row][col] ^ key[l+col][row]);
            }
        }
        
        if (debug) {
            System.out.println("a_rk: \n"+byteMatrixToHex(res));
        }
        return res;
    }
    
    public static byte[][] keySchedule(byte[][] key, boolean debug) {
        final int Nk = 4; // 128-bit key
        final int Nb = 4;
        final int Nr = 10;
        final int wordCount = Nb * (Nr + 1); // 44 words
        
        byte[][] res = new byte[wordCount][4]; // 결과 확장 키
        
        // key를 처음 Nk개의 워드에 복사
        for (int i = 0; i < Nk; i++) {
            for (int j = 0; j < 4; j++) {
                res[i][j] = key[j][i]; // 주의: 열 기준 복사 (key는 열 우선)
            }
        }
        
        byte[] temp = new byte[4];
        
        for (int i = Nk; i < wordCount; i++) {
            // temp = res[i-1]
            for (int j = 0; j < 4; j++) {
                temp[j] = res[i - 1][j];
            }
            
            if (i % Nk == 0) {
                temp = subWord(rotWord(temp)); // RotWord -> SubWord
                temp[0] ^= (byte) RCon[i / Nk]; // RCon 적용은 첫 바이트에 XOR
            }
            
            // w[i] = w[i-Nk] xor temp
            for (int j = 0; j < 4; j++) {
                res[i][j] = (byte) (res[i - Nk][j] ^ temp[j]);
            }
        }
        if (debug) {
            for (byte[] i : res) {
                System.out.println("k_sch: " + gen1.AES.bytesToHex(i));
            }
        }
        return res;
    }
    
    private static byte[] subWord(byte[] w){
        if (w.length != 4) throw new IllegalArgumentException("subWord: Invalid Input Length");
        byte[] res = new byte[4];
        for (int i = 0; i < 4; i++) {
            int b = w[i] & 0xFF;
            int row = (b >> 4) & 0x0F;
            int col = b & 0x0F;
            res[i] = sbox[row][col];
        }
        return res;
    }
    
    private static byte[] rotWord(byte[] w){
        if (w.length != 4) throw new IllegalArgumentException("RotWord: Invalid Input Length");
        byte[] res = new byte[4];
        res[0] = w[1];
        res[1] = w[2];
        res[2] = w[3];
        res[3] = w[0];
        
        return res;
    }
    
    private static byte gmul(int a, byte b) {
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
    
    private static int xtime(int val, int times) {
        for (int i = 0; i < times; i++) {
            val = (val << 1);
            if ((val & 0x100) != 0) {
                val ^= 0x11b;
            }
        }
        return val & 0xff;
    }
    
    public static String byteMatrixToHex(byte[][] matrix) {
        StringBuilder str = new StringBuilder();
        
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                str.append(String.format("%02X ", matrix[row][col]));
            }
            str.append("\n");
        }
        
        return str.toString();
    }
    
    private static final byte[][] sbox = new byte[][] {
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
    private static final byte[][] invSbox = new byte[][] {
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
    
    private static final int[] RCon = {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
    };
    
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
    
    public static byte[][] expandState(byte[] input) {
        byte[][] state = new byte[4][4];
        int index = 0;
        
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] = input[index++];
            }
        }
        
        return state;
    }
}
