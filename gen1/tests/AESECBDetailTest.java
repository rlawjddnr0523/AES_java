package gen1.tests;

import static gen1.AES.addRoundKey;
import static gen1.AES.bytesToHex;
import static gen1.AES.getRoundKey;
import static gen1.AES.mixColumns;
import static gen1.AES.shiftRows;
import static gen1.AES.subBytes;
import static gen1.functions.KeyScedule.keySchedule;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class AESECBDetailTest {
    
    @Test
    public void testAESECBDetail() {
        final byte[] k = new byte[] {
                (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
                (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
                (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
                (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };
        
        final byte[][] ek = new byte[][] {
            // 0라운드 라운드키
            {(byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c},
            // 1라운드 라운드키
            {(byte)0xa0, (byte)0xfa, (byte)0xfe, (byte)0x17,
            (byte)0x88, (byte)0x54, (byte)0x2c, (byte)0xb1,
            (byte)0x23, (byte)0xa3, (byte)0x39, (byte)0x39,
            (byte)0x2a, (byte)0x6c, (byte)0x76, (byte)0x05},
            // 2라운드 라운드키
            {(byte)0xf2, (byte)0xc2, (byte)0x95, (byte)0xf2,
            (byte)0x7a, (byte)0x96, (byte)0xb9, (byte)0x43,
            (byte)0x59, (byte)0x35, (byte)0x80, (byte)0x7a,
            (byte)0x73, (byte)0x59, (byte)0xf6, (byte)0x7f,},
            // 3라운드 라운드키
            {(byte)0x3d, (byte)0x80, (byte)0x47, (byte)0x7d,
            (byte)0x47, (byte)0x16, (byte)0xfe, (byte)0x3e,
            (byte)0x1e, (byte)0x23, (byte)0x7e, (byte)0x44,
            (byte)0x6d, (byte)0x7a, (byte)0x88, (byte)0x3b},
            // 4라운드 라운드키
            {(byte)0xef, (byte)0x44, (byte)0xa5, (byte)0x41,
            (byte)0xa8, (byte)0x52, (byte)0x5b, (byte)0x7f,
            (byte)0xb6, (byte)0x71, (byte)0x25, (byte)0x3b,
            (byte)0xdb, (byte)0x0b, (byte)0xad, (byte)0x00,},
            // 5라운드 라운드키
            {(byte)0xd4, (byte)0xd1, (byte)0xc6, (byte)0xf8,
            (byte)0x7c, (byte)0x83, (byte)0x9d, (byte)0x87,
            (byte)0xca, (byte)0xf2, (byte)0xb8, (byte)0xbc,
            (byte)0x11, (byte)0xf9, (byte)0x15, (byte)0xbc,},
            // 6라운드 라운드키
            {(byte)0x6d, (byte)0x88, (byte)0xa3, (byte)0x7a,
            (byte)0x11, (byte)0x0b, (byte)0x3e, (byte)0xfd,
            (byte)0xdb, (byte)0xf9, (byte)0x86, (byte)0x41,
            (byte)0xca, (byte)0x00, (byte)0x93, (byte)0xfd,},
            // 7라운드 라운드키
            {(byte)0x4e, (byte)0x54, (byte)0xf7, (byte)0x0e,
            (byte)0x5f, (byte)0x5f, (byte)0xc9, (byte)0xf3,
            (byte)0x84, (byte)0xa6, (byte)0x4f, (byte)0xb2,
            (byte)0x4e, (byte)0xa6, (byte)0xdc, (byte)0x4f,},
            // 8라운드 라운드키
            {(byte)0xea, (byte)0xd2, (byte)0x73, (byte)0x21,
            (byte)0xb5, (byte)0x8d, (byte)0xba, (byte)0xd2,
            (byte)0x31, (byte)0x2b, (byte)0xf5, (byte)0x60,
            (byte)0x7f, (byte)0x8d, (byte)0x29, (byte)0x2f,},
            // 9라운드 라운드키
            {(byte)0xac, (byte)0x77, (byte)0x66, (byte)0xf3,
            (byte)0x19, (byte)0xfa, (byte)0xdc, (byte)0x21,
            (byte)0x28, (byte)0xd1, (byte)0x29, (byte)0x41,
            (byte)0x57, (byte)0x5c, (byte)0x00, (byte)0x6e,},
            // 10라운드 라운드키
            {(byte)0xd0, (byte)0x14, (byte)0xf9, (byte)0xa8,
            (byte)0xc9, (byte)0xee, (byte)0x25, (byte)0x89,
            (byte)0xe1, (byte)0x3f, (byte)0x0c, (byte)0xc8,
            (byte)0xb6, (byte)0x63, (byte)0x0c, (byte)0xa6}
        };
        
        byte[] rk = keySchedule(4, k);
        for (int i = 0; i < 11; i++) {
            assertArrayEquals(ek[i], getRoundKey(rk, i),"라운드키 "+i+"이 예상값과 다릅니다.");
            System.out.println("라운드키 "+i+" 통과");
        }
        System.out.println("----------- 키 무결성 테스트에 통과했습니다. -----------");
    }
    
    @Test
    public void testAESECBDetail2() {
        final byte[] p = new byte[] {
                (byte)0x32, (byte)0x43, (byte)0xf6, (byte)0xa8,
                (byte)0x88, (byte)0x5a, (byte)0x30, (byte)0x8d,
                (byte)0x31, (byte)0x31, (byte)0x98, (byte)0xa2,
                (byte)0xe0, (byte)0x37, (byte)0x07, (byte)0x34
        };
        final byte[] k = new byte[] {
                (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
                (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
                (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
                (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
        };
        final byte[][] ec = new byte[][] {
            // 0 round res
            {
                (byte) 0x19, (byte) 0x3d, (byte) 0xe3, (byte) 0xbe,
                (byte) 0xa0, (byte) 0xf4, (byte) 0xe2, (byte) 0x2b,
                (byte) 0x9a, (byte) 0xc6, (byte) 0x8d, (byte) 0x2a,
                (byte) 0xe9, (byte) 0xf8, (byte) 0x48, (byte) 0x08
            },
            // 1 round After SubBytes
            {
                (byte)0xd4, (byte)0x27, (byte)0x11, (byte)0xae,
                (byte)0xe0, (byte)0xbf, (byte)0x98, (byte)0xf1,
                (byte)0xb8, (byte)0xb4, (byte)0x5d, (byte)0xe5,
                (byte)0x1e, (byte)0x41, (byte)0x52, (byte)0x30
            },
            // 1 round After ShiftRows
            {
                (byte)0xd4, (byte)0xbf, (byte)0x5d, (byte)0x30,
                (byte)0xe0, (byte)0xb4, (byte)0x52, (byte)0xae,
                (byte)0xb8, (byte)0x41, (byte)0x11, (byte)0xf1,
                (byte)0x1e, (byte)0x27, (byte)0x98, (byte)0xe5
            },
            // 1 round After MixColumns
            {
                (byte)0x04, (byte)0x66, (byte)0x81, (byte)0xe5,
                (byte)0xe0, (byte)0xcb, (byte)0x19, (byte)0x9a,
                (byte)0x48, (byte)0xf8, (byte)0xd3, (byte)0x7a,
                (byte)0x28, (byte)0x06, (byte)0x26, (byte)0x4c
            },
            // 1 round res
            {
                (byte)0xa4, (byte)0x9c, (byte)0x7f, (byte)0xf2,
                (byte)0x68, (byte)0x9f, (byte)0x35, (byte)0x2b,
                (byte)0x6b, (byte)0x5b, (byte)0xea, (byte)0x43,
                (byte)0x02, (byte)0x6a, (byte)0x50, (byte)0x49
            },
            // 2 round After SubBytes
            {
                (byte)0x49, (byte)0xde, (byte)0xd2, (byte)0x89,
                (byte)0x45, (byte)0xdb, (byte)0x96, (byte)0xf1,
                (byte)0x7f, (byte)0x39, (byte)0x87, (byte)0x1a,
                (byte)0x77, (byte)0x02, (byte)0x53, (byte)0x3b
            },
            // 2 round After ShiftRows
            {
                (byte)0x49, (byte)0xdb, (byte)0x87, (byte)0x3b,
                (byte)0x45, (byte)0x39, (byte)0x53, (byte)0x89,
                (byte)0x7f, (byte)0x02, (byte)0xd2, (byte)0xf1,
                (byte)0x77, (byte)0xde, (byte)0x96, (byte)0x1a
            },
            // 2 round After Mixcolumns
            {
                (byte)0x58, (byte)0x4d, (byte)0xca, (byte)0xf1,
                (byte)0x1b, (byte)0x4b, (byte)0x5a, (byte)0xac,
                (byte)0xdb, (byte)0xe7, (byte)0xca, (byte)0xa8,
                (byte)0x1b, (byte)0x6b, (byte)0xb0, (byte)0xe5
            },
            // 2 round res
            {
                (byte)0xaa, (byte)0x8f, (byte)0x5f, (byte)0x03,
                (byte)0x61, (byte)0xdd, (byte)0xe3, (byte)0xef,
                (byte)0x82, (byte)0xd2, (byte)0x4a, (byte)0xd2,
                (byte)0x68, (byte)0x32, (byte)0x46, (byte)0x9a
            },
            // 3 round After SubBytes
            {
                (byte)0xac, (byte)0x73, (byte)0xcf, (byte)0x7b,
                (byte)0xef, (byte)0xc1, (byte)0x11, (byte)0xdf,
                (byte)0x13, (byte)0xb5, (byte)0xd6, (byte)0xb5,
                (byte)0x45, (byte)0x23, (byte)0x5a, (byte)0xb8,
            },
            // 3 round After ShiftRows
            {
                (byte)0xac, (byte)0xc1, (byte)0xd6, (byte)0xb8,
                (byte)0xef, (byte)0xb5, (byte)0x5a, (byte)0x7b,
                (byte)0x13, (byte)0x23, (byte)0xcf, (byte)0xdf,
                (byte)0x45, (byte)0x73, (byte)0x11, (byte)0xb5,
            },
            // 3 round After Mixcolumns
            {
                (byte)0x75, (byte)0xec, (byte)0x09, (byte)0x93,
                (byte)0x20, (byte)0x0b, (byte)0x63, (byte)0x33,
                (byte)0x53, (byte)0xc0, (byte)0xcf, (byte)0x7c,
                (byte)0xbb, (byte)0x25, (byte)0xd0, (byte)0xdc,
            },
            // 3 round res
            {
                (byte)0x48, (byte)0x6c, (byte)0x4e, (byte)0xee,
                (byte)0x67, (byte)0x1d, (byte)0x9d, (byte)0x0d,
                (byte)0x4d, (byte)0xe3, (byte)0xb1, (byte)0x38,
                (byte)0xd6, (byte)0x5f, (byte)0x58, (byte)0xe7,
            },
            // 4 round After SubBytes
            {
                (byte)0x52, (byte)0x50, (byte)0x2f, (byte)0x28,
                (byte)0x85, (byte)0xa4, (byte)0x5e, (byte)0xd7,
                (byte)0xe3, (byte)0x11, (byte)0xc8, (byte)0x07,
                (byte)0xf6, (byte)0xcf, (byte)0x6a, (byte)0x94,
            },
            // 4 round After ShiftRows
            {
                (byte)0x52, (byte)0xa4, (byte)0xc8, (byte)0x94,
                (byte)0x85, (byte)0x11, (byte)0x6a, (byte)0x28,
                (byte)0xe3, (byte)0xcf, (byte)0x2f, (byte)0xd7,
                (byte)0xf6, (byte)0x50, (byte)0x5e, (byte)0x07,
            },
            // 4 round After Mixcolumns
            {
                (byte)0x0f, (byte)0xd6, (byte)0xda, (byte)0xa9,
                (byte)0x60, (byte)0x31, (byte)0x38, (byte)0xbf,
                (byte)0x6f, (byte)0xc0, (byte)0x10, (byte)0x6b,
                (byte)0x5e, (byte)0xb3, (byte)0x13, (byte)0x01,
            },
            // 4 round res
            {
                (byte)0xe0, (byte)0x92, (byte)0x7f, (byte)0xe8,
                (byte)0xc8, (byte)0x63, (byte)0x63, (byte)0xc0,
                (byte)0xd9, (byte)0xb1, (byte)0x35, (byte)0x50,
                (byte)0x85, (byte)0xb8, (byte)0xbe, (byte)0x01,
            },
            // 5 round After SubBytes
            {
                (byte)0xe1, (byte)0x4f, (byte)0xd2, (byte)0x9b,
                (byte)0xe8, (byte)0xfb, (byte)0xfb, (byte)0xba,
                (byte)0x35, (byte)0xc8, (byte)0x96, (byte)0x53,
                (byte)0x97, (byte)0x6c, (byte)0xae, (byte)0x7c,
            },
            // 5 round After ShiftRows
            {
                (byte)0xe1, (byte)0xfb, (byte)0x96, (byte)0x7c,
                (byte)0xe8, (byte)0xc8, (byte)0xae, (byte)0x9b,
                (byte)0x35, (byte)0x6c, (byte)0xd2, (byte)0xba,
                (byte)0x97, (byte)0x4f, (byte)0xfb, (byte)0x53,
            },
            // 5 round After Mixcolumns
            {
                (byte)0x25, (byte)0xd1, (byte)0xa9, (byte)0xad,
                (byte)0xbd, (byte)0x11, (byte)0xd1, (byte)0x68,
                (byte)0xb6, (byte)0x3a, (byte)0x33, (byte)0x8e,
                (byte)0x4c, (byte)0x4c, (byte)0xc0, (byte)0xb0,
            },
            // 5 round res
            {
                (byte)0xf1, (byte)0x00, (byte)0x6f, (byte)0x55,
                (byte)0xc1, (byte)0x92, (byte)0x4c, (byte)0xef,
                (byte)0x7c, (byte)0xc8, (byte)0x8b, (byte)0x32,
                (byte)0x5d, (byte)0xb5, (byte)0xd5, (byte)0x0c,
            },
            // 6 round After SubBytes
            {
                (byte)0xa1, (byte)0x63, (byte)0xa8, (byte)0xfc,
                (byte)0x78, (byte)0x4f, (byte)0x29, (byte)0xdf,
                (byte)0x10, (byte)0xe8, (byte)0x3d, (byte)0x23,
                (byte)0x4c, (byte)0xd5, (byte)0x03, (byte)0xfe,
            },
            // 6 round After ShiftRows
            {
                (byte)0xa1, (byte)0x4f, (byte)0x3d, (byte)0xfe,
                (byte)0x78, (byte)0xe8, (byte)0x03, (byte)0xfc,
                (byte)0x10, (byte)0xd5, (byte)0xa8, (byte)0xdf,
                (byte)0x4c, (byte)0x63, (byte)0x29, (byte)0x23,
            },
            // 6 round After Mixcolumns
            {
                (byte)0x4b, (byte)0x86, (byte)0x8d, (byte)0x6d,
                (byte)0x2c, (byte)0x4a, (byte)0x89, (byte)0x80,
                (byte)0x33, (byte)0x9d, (byte)0xf4, (byte)0xe8,
                (byte)0x37, (byte)0xd2, (byte)0x18, (byte)0xd8,
            },
            // 6 round res
            {
                (byte)0x26, (byte)0x0e, (byte)0x2e, (byte)0x17,
                (byte)0x3d, (byte)0x41, (byte)0xb7, (byte)0x7d,
                (byte)0xe8, (byte)0x64, (byte)0x72, (byte)0xa9,
                (byte)0xfd, (byte)0xd2, (byte)0x8b, (byte)0x25,
            },
            // 7 round After SubBytes
            {
                (byte)0xf7, (byte)0xab, (byte)0x31, (byte)0xf0,
                (byte)0x27, (byte)0x83, (byte)0xa9, (byte)0xff,
                (byte)0x9b, (byte)0x43, (byte)0x40, (byte)0xd3,
                (byte)0x54, (byte)0xb5, (byte)0x3d, (byte)0x3f,
            },
            // 7 round After ShiftRows
            {
                (byte)0xf7, (byte)0x83, (byte)0x40, (byte)0x3f,
                (byte)0x27, (byte)0x43, (byte)0x3d, (byte)0xf0,
                (byte)0x9b, (byte)0xb5, (byte)0x31, (byte)0xff,
                (byte)0x54, (byte)0xab, (byte)0xa9, (byte)0xd3,
            },
            // 7 round After Mixcolumns
            {
                (byte)0x14, (byte)0x15, (byte)0xb5, (byte)0xbf,
                (byte)0x46, (byte)0x16, (byte)0x15, (byte)0xec,
                (byte)0x27, (byte)0x46, (byte)0x56, (byte)0xd7,
                (byte)0x34, (byte)0x2a, (byte)0xd8, (byte)0x43,
            },
            // 7 round res
            {
                (byte)0x5a, (byte)0x41, (byte)0x42, (byte)0xb1,
                (byte)0x19, (byte)0x49, (byte)0xdc, (byte)0x1f,
                (byte)0xa3, (byte)0xe0, (byte)0x19, (byte)0x65,
                (byte)0x7a, (byte)0x8c, (byte)0x04, (byte)0x0c,
            },
            // 8 round After SubBytes
            {
                (byte)0xbe, (byte)0x83, (byte)0x2c, (byte)0xc8,
                (byte)0xd4, (byte)0x3b, (byte)0x86, (byte)0xc0,
                (byte)0x0a, (byte)0xe1, (byte)0xd4, (byte)0x4d,
                (byte)0xda, (byte)0x64, (byte)0xf2, (byte)0xfe,
            },
            // 8 round After ShiftRows
            {
                (byte)0xbe, (byte)0x3b, (byte)0xd4, (byte)0xfe,
                (byte)0xd4, (byte)0xe1, (byte)0xf2, (byte)0xc8,
                (byte)0x0a, (byte)0x64, (byte)0x2c, (byte)0xc0,
                (byte)0xda, (byte)0x83, (byte)0x86, (byte)0x4d,
            },
            // 8 round After Mixcolumns
            {
                (byte)0x00, (byte)0x51, (byte)0x2f, (byte)0xd1,
                (byte)0xb1, (byte)0xc8, (byte)0x89, (byte)0xff,
                (byte)0x54, (byte)0x76, (byte)0x6d, (byte)0xcd,
                (byte)0xfa, (byte)0x1b, (byte)0x99, (byte)0xea,
            },
            // 8 round res
            {
                (byte)0xea, (byte)0x83, (byte)0x5c, (byte)0xf0,
                (byte)0x04, (byte)0x45, (byte)0x33, (byte)0x2d,
                (byte)0x65, (byte)0x5d, (byte)0x98, (byte)0xad,
                (byte)0x85, (byte)0x96, (byte)0xb0, (byte)0xc5,
            },
            // 9 round After SubBytes
            {
                (byte)0x87, (byte)0xec, (byte)0x4a, (byte)0x8c,
                (byte)0xf2, (byte)0x6e, (byte)0xc3, (byte)0xd8,
                (byte)0x4d, (byte)0x4c, (byte)0x46, (byte)0x95,
                (byte)0x97, (byte)0x90, (byte)0xe7, (byte)0xa6,
            },
            // 9 round After ShiftRows
            {
                (byte)0x87, (byte)0x6e, (byte)0x46, (byte)0xa6,
                (byte)0xf2, (byte)0x4c, (byte)0xe7, (byte)0x8c,
                (byte)0x4d, (byte)0x90, (byte)0x4a, (byte)0xd8,
                (byte)0x97, (byte)0xec, (byte)0xc3, (byte)0x95,
            },
            // 9 round After Mixcolumns
            {
                (byte)0x47, (byte)0x37, (byte)0x94, (byte)0xed,
                (byte)0x40, (byte)0xd4, (byte)0xe4, (byte)0xa5,
                (byte)0xa3, (byte)0x70, (byte)0x3a, (byte)0xa6,
                (byte)0x4c, (byte)0x9f, (byte)0x42, (byte)0xbc,
            },
            // 9 round res
            {
                (byte)0xeb, (byte)0x40, (byte)0xf2, (byte)0x1e,
                (byte)0x59, (byte)0x2e, (byte)0x38, (byte)0x84,
                (byte)0x8b, (byte)0xa1, (byte)0x13, (byte)0xe7,
                (byte)0x1b, (byte)0xc3, (byte)0x42, (byte)0xd2,
            },
            // 10 round After SubBytes
            {
                (byte)0xe9, (byte)0x09, (byte)0x89, (byte)0x72,
                (byte)0xcb, (byte)0x31, (byte)0x07, (byte)0x5f,
                (byte)0x3d, (byte)0x32, (byte)0x7d, (byte)0x94,
                (byte)0xaf, (byte)0x2e, (byte)0x2c, (byte)0xb5,
            },
            // 10 round After ShiftRows
            {
                (byte)0xe9, (byte)0x31, (byte)0x7d, (byte)0xb5,
                (byte)0xcb, (byte)0x32, (byte)0x2c, (byte)0x72,
                (byte)0x3d, (byte)0x2e, (byte)0x89, (byte)0x5f,
                (byte)0xaf, (byte)0x09, (byte)0x07, (byte)0x94,
            },
            // 10 round res
            {
                (byte)0x39, (byte)0x25, (byte)0x84, (byte)0x1d,
                (byte)0x02, (byte)0xdc, (byte)0x09, (byte)0xfb,
                (byte)0xdc, (byte)0x11, (byte)0x85, (byte)0x97,
                (byte)0x19, (byte)0x6a, (byte)0x0b, (byte)0x32,
            },
        };
        byte[] rk = keySchedule(4, k);
        byte[] res = addRoundKey(p, getRoundKey(rk, 0));
        System.out.println("-------0라운드-------");
        assertArrayEquals(ec[0], res, "0라운드 결과가 다릅니다.");
        System.out.println("0라운드 addRoundKey 통과");
        System.out.println("-----0라운드 통과-----");
        
        int ecIndex = 1;
        for (int round = 1; round < 10; round++) {
            System.out.println("-------"+round+"라운드-------");
            res = subBytes(res);
            assertArrayEquals(ec[ecIndex], res, round+"라운드 subBytes 결과에 이상이있습니다.\n 결과값: "
                + Arrays.toString(res) + "\n 예상값: " + Arrays.toString(ec[ecIndex]) + "\n");
            System.out.println(round+"라운드 subBytes 통과");
            ecIndex++;
            
            res = shiftRows(res);
            assertArrayEquals(ec[ecIndex], res, round+"라운드 shiftRows 결과에 이상이있습니다.\n 결과값: "
                + Arrays.toString(res) + "\n 예상값: " + Arrays.toString(ec[ecIndex]) + "\n");
            System.out.println(round+"라운드 shiftRows 통과");
            ecIndex++;
            
            res = mixColumns(res);
            assertArrayEquals(ec[ecIndex], res, round+"라운드 mixColumns 결과에 이상이있습니다.\n 결과값: "
                + Arrays.toString(res) + "\n 예상값: " + Arrays.toString(ec[ecIndex]) + "\n");
            System.out.println(round+"라운드 mixColumns 통과");
            ecIndex++;
            
            res = addRoundKey(res, getRoundKey(rk, round));
            assertArrayEquals(ec[ecIndex], res, round+"라운드 addRoundKey 결과에 이상이있습니다.\n 결과값: "
                + Arrays.toString(res) + "\n 예상값: " + Arrays.toString(ec[ecIndex]) + "\n");
            System.out.println(round+"라운드 addRoundKey 통과");
            ecIndex++;
            
            System.out.println("-----"+round+"라운드 통과-----");
        }
        
        System.out.println("-------10라운드-------");
        res = subBytes(res);
        assertArrayEquals(ec[ecIndex], res, "10라운드 subBytes 결과에 이상이있습니다.");
        System.out.println("10라운드 subBytes 통과");
        ecIndex++;
        
        res = shiftRows(res);
        assertArrayEquals(ec[ecIndex], res, "10라운드 shiftRows 결과에 이상이있습니다.");
        System.out.println("10라운드 shiftRows 통과");
        ecIndex++;
        
        res = addRoundKey(res, getRoundKey(rk, 10));
        assertArrayEquals(ec[ecIndex], res, "10라운드 addRoundKey 결과에 이상이있습니다.");
        System.out.println("10라운드 addRoundKey 통과");
        System.out.println("-----10라운드 통과-----");
        
        System.out.println("모든 과정에 통과했습니다.");
    }
}
