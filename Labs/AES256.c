//Archit Agrawal
//202051213

#include<stdio.h>
#define uint16_t unsigned short int
#define uint32_t unsigned long int
#define uint64_t unsigned long long int
#define uchar_t unsigned char

const uint16_t G = 0x011b;

uchar_t subbyte_table[16][16] = {
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

const uchar_t M[4][4] = {{0x02, 0x03, 0x01, 0x01}, {0x01, 0x02, 0x03, 0x01}, {0x01, 0x01, 0x02, 0x03}, {0x03, 0x01, 0x01, 0x02}};
const uint32_t RCON[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

uchar_t subbyte(uchar_t x){
    uint16_t t2 = x & 15;
    uint16_t t1 = x >> 4;
    return subbyte_table[t1][t2];
}

uchar_t inverseSubbyte(uchar_t x){
    uint16_t t2 = x & 15;
    uint16_t t1 = x >> 4;
    uchar_t inv = 0;
    for(uchar_t i = 0; i < 16; i++){
        for(uchar_t j = 0; j < 16; j++){
            if(subbyte_table[i][j] == x){
                return ((i << 4) | j);
            }
        }
    }
    return 0;
}

void shiftRow(uchar_t s[4][4]){
    for(int i = 1; i < 4; i++){
        uchar_t temp[4];
        for(int j = 0; j < 4; j++) temp[j] = s[i][j];
        for(int j = 0; j < 4; j++){
            s[i][j] = temp[(j + i) % 4];
        }
    }
}

void invShiftRow(uchar_t s[4][4]){
    for(int i = 1; i < 4; i++){
        uchar_t temp[4];
        for(int j = 0; j < 4; j++) temp[j] = s[i][j];
        for(int j = 0; j < 4; j++){
            s[i][j] = temp[(j + 4 - i) % 4];
        }
    }
}

uchar_t xTimesS(uchar_t x){
    uchar_t temp = x << 1;
    if(x >> 7) temp = temp ^ (0x1b);
    return temp;
}

void mixColumns(uchar_t s[4][4]){
    for(int i = 0; i < 4; i++){
        uchar_t t1 = xTimesS(s[0][i]) ^ xTimesS(s[1][i]) ^ s[1][i] ^ s[2][i] ^ s[3][i];
        uchar_t t2 = s[0][i] ^ xTimesS(s[1][i]) ^ xTimesS(s[2][i]) ^ s[2][i] ^ s[3][i];
        uchar_t t3 = s[0][i] ^ s[1][i] ^ xTimesS(s[2][i]) ^ xTimesS(s[3][i]) ^ s[3][i];
        uchar_t t4 = xTimesS(s[0][i]) ^ s[0][i] ^ s[1][i] ^ s[2][i] ^ xTimesS(s[3][i]);

        s[0][i] = t1;
        s[1][i] = t2;
        s[2][i] = t3;
        s[3][i] = t4;
    }
}

void invMixCols(uchar_t s[4][4]){
    mixColumns(s);
    mixColumns(s);
    mixColumns(s);
}

uint32_t rotWord(uint32_t x){
    uchar_t z = 0xff;
    uchar_t temp = (x >> 24) & z;
    x = (x << 8) | temp;
    return x;
}

uint32_t subWord(uint32_t x){
    uchar_t z = 0xff;
    uchar_t x0, x1, x2, x3;
    x0 = (x >> 24) & z;
    x1 = (x >> 16) & z;
    x2 = (x >> 8) & z;
    x3 = x & z;

    x0 = subbyte(x0);
    x1 = subbyte(x1);
    x2 = subbyte(x2);
    x3 = subbyte(x3);

    x = (x0 << 24) | (x1 << 16) | (x2 << 8) | x3;
    return x;
}

void keyScheduling(uchar_t key[32], uchar_t roundKeys[15][4][4]){
    uint32_t words[60];
    uchar_t z = 0xff;

    for(int i = 0; i < 8; i++){
        words[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | (key[4*i+3]);
    }

    for(int i = 8; i < 60; i++){
        uint32_t temp = words[i-1];
        if(i % 8 == 0) temp = subWord(rotWord(temp)) ^ (RCON[i/8 - 1]);
        else if(i % 8 == 4) temp = subWord(temp);
        words[i] = words[i - 8] ^ temp;
    }
    
    for(int i = 0; i < 15; i++){
        for(int j = 0; j < 4; j++){
            for(int k = 0; k < 4; k++){
                roundKeys[i][k][j] = (words[4*i+j] >> (24 - 8 * k)) & z;
            }
        }
    }
}

void roundFunction(int round, uchar_t s[4][4]){
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s[i][j] = subbyte(s[i][j]);
        }
    }
    shiftRow(s);
    if(round < 14) mixColumns(s);
}

void inverseRoundFunction(int round, uchar_t s[4][4]){
    if(round != 14) invMixCols(s);

    invShiftRow(s);
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s[i][j] = inverseSubbyte(s[i][j]);
        }
    }
}


void encryptAES(uchar_t plaintext[16], uchar_t key[32], uchar_t ciphertext[16]){
    uchar_t s[4][4];

    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s[j][i] = plaintext[i * 4 + j];
        }
    }
    
    uchar_t roundKeys[15][4][4];
    keyScheduling(key, roundKeys);

    for(int i = 0; i < 15; i++){
        for(int j = 0; j < 4; j++){
            for(int x = 0; x < 4; x++){
                s[j][x] = s[j][x] ^ roundKeys[i][j][x];
            }
        }
        
        if(i < 14) roundFunction(i+1, s);
    }

    int index = 0;
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            ciphertext[index++] = s[j][i];
        }
    }
}

void decryptAES(uchar_t ciphertext[16], uchar_t key[32], uchar_t decrypted_text[16]){
    uchar_t s[4][4];

    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s[j][i] = ciphertext[i * 4 + j];
        }
    }
    
    uchar_t roundKeys[15][4][4];
    keyScheduling(key, roundKeys);

    for(int i = 14; i >= 0; i--){
        for(int j = 0; j < 4; j++){
            for(int x = 0; x < 4; x++){
                s[j][x] = s[j][x] ^ roundKeys[i][j][x];
            }
        }

        if(i > 0) inverseRoundFunction(i, s);
    }

    int index = 0;
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            decrypted_text[index++] = s[j][i];
        }
    }
}

void print(uchar_t s[16]){
    for(int i = 0; i < 16; i++){
        printf("%02x ", s[i]);
    }
    printf("\n");
}


int main(){
    uchar_t plaintext[16];

    printf("Enter 128-bit plaintext as input (in hexadecimal, each pair of hex digits separated by spaces): ");
    for(int i = 0; i < 16; i++) {
        scanf("%hhx", &plaintext[i]);    
    }
 
    uchar_t key[32]; // = {0x95, 0x65, 0xfd, 0xf3, 0xa0, 0x12, 0x39, 0xcd, 0x29, 0xff, 0xae, 0x28, 0xc2, 0xa9, 0xd1, 0xc4};
    printf("Enter 256-bit key as input (in hexadecimal, each pair of hex digits separated by spaces): ");
    for(int i = 0; i < 32; i++){
        scanf("%hhx", &key[i]);
    }

    uchar_t roundKey[15][4][4];
    keyScheduling(key, roundKey);

    printf("Plaintext: ");
    print(plaintext);
    printf("Key: ");
    print(key);

    uchar_t ciphertext[16];
    encryptAES(plaintext, key, ciphertext);
    
    printf("Ciphertext: ");
    print(ciphertext);

    uchar_t decrypted_text[16];
    decryptAES(ciphertext, key, decrypted_text);
    printf("Decrypted Text: ");
    print(decrypted_text);
   
    return 0;
}

//  81 82 9c a6 d3 81 67 c9 f2 ff 67 8a e0 ed bb 12
// ab 12 8c e9 ba d7 53 26 b0 97 b6 b1 24 39 ac 12
