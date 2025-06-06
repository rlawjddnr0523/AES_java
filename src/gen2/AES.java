package gen2;

public class AES {
    public static void main(String[] args) {
        byte[][] P = new byte[][] {
                {(byte)0x00, (byte)0x44, (byte)0x88, (byte)0xcc},
                {(byte)0x11, (byte)0x55, (byte)0x99, (byte)0xdd},
                {(byte)0x22, (byte)0x66, (byte)0xaa, (byte)0xee},
                {(byte)0x33, (byte)0x77, (byte)0xbb, (byte)0xff},
        };
        byte[][] K = new byte[][] {
                {(byte)0x2b, (byte)0x28, (byte)0xab, (byte)0x09},
                {(byte)0x7e, (byte)0xae, (byte)0xf7, (byte)0xcf},
                {(byte)0x15, (byte)0xd2, (byte)0x15, (byte)0x4f},
                {(byte)0x16, (byte)0xa6, (byte)0x88, (byte)0x3c}
        };
//        byte[][] K = Functions.expandState(gen1.functions.AESKeyGenerator.generateRandomAESKey());
        
        int Nb = 4; // Number Of Columns (32-bit words) comprising the State
        int Nk = 4; // Number Of 32-bit words comprising the Cipher Key
        int Nr = 10; // Number Of Rounds
        
        System.out.println("Plain: "+gen1.AES.bytesToHex(Functions.flattenState(P)));
        System.out.println("Key  : "+gen1.AES.bytesToHex(Functions.flattenState(K)));
        
        byte[][] RK = Functions.keySchedule(K, true);
        byte[][] res = Functions.addRoundKey(P, RK, 0, false);
//        System.out.println("round[1].start: \n"+Functions.byteMatrixToHex(res));
        for (int i = 1; i < 10; i++) {
            res = Functions.subBytes(res, false);
            res = Functions.shiftRows(res, false);
            res = Functions.mixColumns(res, false);
            res = Functions.addRoundKey(res, RK, i, false);
//            System.out.println("round["+(i+1)+"].start: \n"+Functions.byteMatrixToHex(res));
        }
        res = Functions.subBytes(res, false);
        res = Functions.shiftRows(res, false);
        res = Functions.addRoundKey(res, RK, 10, false);
        
        System.out.println("inc_output: "+gen1.AES.bytesToHex(Functions.flattenState(res)));
        
        res = Functions.addRoundKey(res, RK, 10, false);
//        System.out.println("round[1].istart: \n"+Functions.byteMatrixToHex(res));
        for (int i = 9; i > 0; i--) {
            res = Functions.invShiftRows(res, false);
            res = Functions.invSubBytes(res, false);
            res = Functions.addRoundKey(res, RK, i, false);
            res = Functions.invMixColumns(res, false);
//            System.out.println("round["+(11-i)+"].istart: \n"+Functions.byteMatrixToHex(res));
        }
        res = Functions.invShiftRows(res, false);
        res = Functions.invSubBytes(res, false);
        res = Functions.addRoundKey(res, RK, 0, false);
        
        System.out.println("dec_output: "+gen1.AES.bytesToHex(Functions.flattenState(res)));
    }
}
