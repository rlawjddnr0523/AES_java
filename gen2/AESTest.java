package gen2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class AESTest {
    
    @Test
    public void value(){
        byte[][] P = new byte[][] {
                {(byte)0x00, (byte)0x44, (byte)0x88, (byte)0xcc},
                {(byte)0x11, (byte)0x55, (byte)0x99, (byte)0xdd},
                {(byte)0x22, (byte)0x66, (byte)0xaa, (byte)0xee},
                {(byte)0x33, (byte)0x77, (byte)0xbb, (byte)0xff},
        };
        byte[][] K = new byte[][] {
                {(byte)0x00, (byte)0x04, (byte)0x08, (byte)0x0c},
                {(byte)0x01, (byte)0x05, (byte)0x09, (byte)0x0d},
                {(byte)0x02, (byte)0x06, (byte)0x0a, (byte)0x0e},
                {(byte)0x03, (byte)0x07, (byte)0x0b, (byte)0x0f}
        };
        byte[][] ee = new byte[][] {
                {(byte)0x00,(byte)0x10,(byte)0x20,(byte)0x30,(byte)0x40,(byte)0x50,(byte)0x60,(byte)0x70,(byte)0x80,(byte)0x90,(byte)0xa0,(byte)0xb0,(byte)0xc0,(byte)0xd0,(byte)0xe0,(byte)0xf0},
                {(byte)0x89,(byte)0xd8,(byte)0x10,(byte)0xe8,(byte)0x85,(byte)0x5a,(byte)0xce,(byte)0x68,(byte)0x2d,(byte)0x18,(byte)0x43,(byte)0xd8,(byte)0xcb,(byte)0x12,(byte)0x8f,(byte)0xe4},
                {(byte)0x49,(byte)0x15,(byte)0x59,(byte)0x8f,(byte)0x55,(byte)0xe5,(byte)0xd7,(byte)0xa0,(byte)0xda,(byte)0xca,(byte)0x94,(byte)0xfa,(byte)0x1f,(byte)0x0a,(byte)0x63,(byte)0xf7},
                {(byte)0xfa,(byte)0x63,(byte)0x6a,(byte)0x28,(byte)0x25,(byte)0xb3,(byte)0x39,(byte)0xc9,(byte)0x40,(byte)0x66,(byte)0x8a,(byte)0x31,(byte)0x57,(byte)0x24,(byte)0x4d,(byte)0x17},
                {(byte)0x24,(byte)0x72,(byte)0x40,(byte)0x23,(byte)0x69,(byte)0x66,(byte)0xb3,(byte)0xfa,(byte)0x6e,(byte)0xd2,(byte)0x75,(byte)0x32,(byte)0x88,(byte)0x42,(byte)0x5b,(byte)0x6c},
                {(byte)0xc8,(byte)0x16,(byte)0x77,(byte)0xbc,(byte)0x9b,(byte)0x7a,(byte)0xc9,(byte)0x3b,(byte)0x25,(byte)0x02,(byte)0x79,(byte)0x92,(byte)0xb0,(byte)0x26,(byte)0x19,(byte)0x96},
                {(byte)0xc6,(byte)0x2f,(byte)0xe1,(byte)0x09,(byte)0xf7,(byte)0x5e,(byte)0xed,(byte)0xc3,(byte)0xcc,(byte)0x79,(byte)0x39,(byte)0x5d,(byte)0x84,(byte)0xf9,(byte)0xcf,(byte)0x5d},
                {(byte)0xd1,(byte)0x87,(byte)0x6c,(byte)0x0f,(byte)0x79,(byte)0xc4,(byte)0x30,(byte)0x0a,(byte)0xb4,(byte)0x55,(byte)0x94,(byte)0xad,(byte)0xd6,(byte)0x6f,(byte)0xf4,(byte)0x1f},
                {(byte)0xfd,(byte)0xe3,(byte)0xba,(byte)0xd2,(byte)0x05,(byte)0xe5,(byte)0xd0,(byte)0xd7,(byte)0x35,(byte)0x47,(byte)0x96,(byte)0x4e,(byte)0xf1,(byte)0xfe,(byte)0x37,(byte)0xf1},
                {(byte)0xbd,(byte)0x6e,(byte)0x7c,(byte)0x3d,(byte)0xf2,(byte)0xb5,(byte)0x77,(byte)0x9e,(byte)0x0b,(byte)0x61,(byte)0x21,(byte)0x6e,(byte)0x8b,(byte)0x10,(byte)0xb6,(byte)0x89},
                {(byte)0x69,(byte)0xc4,(byte)0xe0,(byte)0xd8,(byte)0x6a,(byte)0x7b,(byte)0x04,(byte)0x30,(byte)0xd8,(byte)0xcd,(byte)0xb7,(byte)0x80,(byte)0x70,(byte)0xb4,(byte)0xc5,(byte)0x5a},
        };
        byte[][] ed = new byte[][] {
                {(byte)0x7a,(byte)0xd5,(byte)0xfd,(byte)0xa7,(byte)0x89,(byte)0xef,(byte)0x4e,(byte)0x27,(byte)0x2b,(byte)0xca,(byte)0x10,(byte)0x0b,(byte)0x3d,(byte)0x9f,(byte)0xf5,(byte)0x9f},
                {(byte)0x54,(byte)0xd9,(byte)0x90,(byte)0xa1,(byte)0x6b,(byte)0xa0,(byte)0x9a,(byte)0xb5,(byte)0x96,(byte)0xbb,(byte)0xf4,(byte)0x0e,(byte)0xa1,(byte)0x11,(byte)0x70,(byte)0x2f},
                {(byte)0x3e,(byte)0x1c,(byte)0x22,(byte)0xc0,(byte)0xb6,(byte)0xfc,(byte)0xbf,(byte)0x76,(byte)0x8d,(byte)0xa8,(byte)0x50,(byte)0x67,(byte)0xf6,(byte)0x17,(byte)0x04,(byte)0x95},
                {(byte)0xb4,(byte)0x58,(byte)0x12,(byte)0x4c,(byte)0x68,(byte)0xb6,(byte)0x8a,(byte)0x01,(byte)0x4b,(byte)0x99,(byte)0xf8,(byte)0x2e,(byte)0x5f,(byte)0x15,(byte)0x55,(byte)0x4c},
                {(byte)0xe8,(byte)0xda,(byte)0xb6,(byte)0x90,(byte)0x14,(byte)0x77,(byte)0xd4,(byte)0x65,(byte)0x3f,(byte)0xf7,(byte)0xf5,(byte)0xe2,(byte)0xe7,(byte)0x47,(byte)0xdd,(byte)0x4f},
                {(byte)0x36,(byte)0x33,(byte)0x9d,(byte)0x50,(byte)0xf9,(byte)0xb5,(byte)0x39,(byte)0x26,(byte)0x9f,(byte)0x2c,(byte)0x09,(byte)0x2d,(byte)0xc4,(byte)0x40,(byte)0x6d,(byte)0x23},
                {(byte)0x2d,(byte)0x6d,(byte)0x7e,(byte)0xf0,(byte)0x3f,(byte)0x33,(byte)0xe3,(byte)0x34,(byte)0x09,(byte)0x36,(byte)0x02,(byte)0xdd,(byte)0x5b,(byte)0xfb,(byte)0x12,(byte)0xc7},
                {(byte)0x3b,(byte)0xd9,(byte)0x22,(byte)0x68,(byte)0xfc,(byte)0x74,(byte)0xfb,(byte)0x73,(byte)0x57,(byte)0x67,(byte)0xcb,(byte)0xe0,(byte)0xc0,(byte)0x59,(byte)0x0e,(byte)0x2d},
                {(byte)0xa7,(byte)0xbe,(byte)0x1a,(byte)0x69,(byte)0x97,(byte)0xad,(byte)0x73,(byte)0x9b,(byte)0xd8,(byte)0xc9,(byte)0xca,(byte)0x45,(byte)0x1f,(byte)0x61,(byte)0x8b,(byte)0x61},
                {(byte)0x63,(byte)0x53,(byte)0xe0,(byte)0x8c,(byte)0x09,(byte)0x60,(byte)0xe1,(byte)0x04,(byte)0xcd,(byte)0x70,(byte)0xb7,(byte)0x51,(byte)0xba,(byte)0xca,(byte)0xd0,(byte)0xe7},
                {(byte)0x00,(byte)0x11,(byte)0x22,(byte)0x33,(byte)0x44,(byte)0x55,(byte)0x66,(byte)0x77,(byte)0x88,(byte)0x99,(byte)0xaa,(byte)0xbb,(byte)0xcc,(byte)0xdd,(byte)0xee,(byte)0xff},
        };
        
        byte[][] RK = Functions.keySchedule(K, true);
        byte[][] res = Functions.addRoundKey(P, RK, 0, false);
        System.out.println("======0======");
        System.out.println("Expected: "+gen1.AES.bytesToHex(ee[0]));
        System.out.println("res     : "+gen1.AES.bytesToHex(Functions.flattenState(res)));
        assertArrayEquals(ee[0], Functions.flattenState(res), "location: r0_adk");
        
        for (int round = 1; round < 10; round++) {
            System.out.println("======"+round+"======");
            res = Functions.subBytes(res, false);
            res = Functions.shiftRows(res, false);
            res = Functions.mixColumns(res, false);
            res = Functions.addRoundKey(res, RK, round, false);
            System.out.println("Expected: "+gen1.AES.bytesToHex(ee[round]));
            System.out.println("res     : "+gen1.AES.bytesToHex(Functions.flattenState(res)));
            assertArrayEquals(ee[round], Functions.flattenState(res), "location: r"+round+"_adk");
        }
        System.out.println("======10======");
        res = Functions.subBytes(res, false);
        res = Functions.shiftRows(res, false);
        res = Functions.addRoundKey(res, RK, 10, false);
        System.out.println("Expected: "+gen1.AES.bytesToHex(ee[10]));
        System.out.println("res     : "+gen1.AES.bytesToHex(Functions.flattenState(res)));
        assertArrayEquals(ee[10], Functions.flattenState(res), "location: r10_adk");
        
        System.out.println("======Decipher======");
        res = Functions.addRoundKey(res, RK, 10, false);
        System.out.println("Expected: "+gen1.AES.bytesToHex(ed[0]));
        System.out.println("res     : "+gen1.AES.bytesToHex(Functions.flattenState(res)));
        assertArrayEquals(ed[0], Functions.flattenState(res), "location: r0_iadk");
        int edIndex = 1;
        for (int round = 9; round > 0; round--) {
            System.out.println("======i"+edIndex+"======");
            res = Functions.invShiftRows(res, false);
            res = Functions.invSubBytes(res, false);
            res = Functions.addRoundKey(res, RK, round, false);
            res = Functions.invMixColumns(res, false);
            System.out.println("Expected: "+gen1.AES.bytesToHex(ed[edIndex]));
//            System.out.println("Expected: "+Arrays.toString(ed[edIndex]));
            System.out.println("res     : "+gen1.AES.bytesToHex(Functions.flattenState(res)));
//            System.out.println("res     : "+Arrays.toString(Functions.flattenState(res)));
            assertArrayEquals(ed[edIndex], Functions.flattenState(res), "location: r"+edIndex+"_iadk");
            edIndex++;
        }
        res = Functions.invShiftRows(res, false);
        res = Functions.invSubBytes(res, false);
        res = Functions.addRoundKey(res, RK, 0, false);
        assertArrayEquals(ed[edIndex], Functions.flattenState(res), "location: r10_iadk");
        
        System.out.println("=======END======");
        System.out.println("Expected: "+gen1.AES.bytesToHex(ed[10]));
        System.out.println("res     : "+gen1.AES.bytesToHex(Functions.flattenState(res)));
        System.out.println("테스트 벡터(FIPS 197 Appendix C.1 참고) 실행 성공");
    }
}
