#include<stdio.h>

//preprocessors
#define uint16_t unsigned short int
#define uint32_t unsigned long int
#define uint64_t unsigned long long int
#define uchar_t unsigned char

/*
Coded by: Archit Agrawal (202051213)
This code implements AES-prime. AES-prime is a modification of AES as described in the assignment.
The subbyte function and the mix column function in AES-prime are modified as compared to standard AES-128.
*/

//the primitive polynomial of AES stored as binary
// G(x) = x^8 + x^4 + x^3 + x + 1 = (0000 0001 0001 1011) = 0x11b
const uint16_t G = 0x011b;

//the subbyte table used in AES
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

// the round constants for AES-prime, they are exactly similar to AES-128.
const uint32_t RCON[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

/* 
First, let's understand here that how the product of two polynomials is taken.
Let's say, the two polynomial are: P1 = x^7 + x^5 and P2 = x^2 + x + 1
The corresponding binary strings are: P1 = a = 10100000 and P2 = b = 00000111

Now, to find the product, what we do is:
z1 = P1 * x^2
z2 = P1 * x
z3 = P1 * 1
product  = z1 + z2 + z3 = P1 * (x^2 + x + 1)

we will replicate the same thing here, since polynomials are represented as binary string, with ith bit set if polynomial has x^i.
therefore, we will multiply b with each x^i set in a and keep adding it. Since, the add (or subtraction) operation is xor in F2[x],
and multiplying with x^i is the left shift operation by i bits, the function can be implemented as given below.
*/

//this function return the product of two polynomials
//the input are two polynomials (deg <= 7), therfore, the output can be a polynomial of maximum degree 15
uint16_t product(uchar_t a, uchar_t b){
    uint16_t prod = 0; //stores the product

    for(int i = 0; i < 8; i++){  //running the loop from 0 to 7 as max degree of a is 7
        if((a >> i) & 1){        //checking if a has x^i, i.e., its ith bit is set
            uint16_t x = b << i;  //if x^i is in a, then multiply it with b
            prod = prod ^ x;      //and add it in the product
        }
    }
    return prod;
}
//Note: this function just returns the product of two polynomials, it does not take the modulus of the output with G(x)

/* 
The sub-byte function in AES-prime is modified from AES-128. Here, suppose we received inp as input to subbyte function.
In AES-128, we used to take the most significant 4 bits as row number(r) and least significant 4 bits as column number(c),
Then, we returned the value at table[r][c].
But, here we have to first perform (2 * inp + 1) mod G(x), the output of this will be a 8-bit number. Now, we have to do the table
lookup as we did in Subbyte of AES-128. Here, (2) = (10) in binary = (x) as polynomial, and 1 is the polynomial 1.
Therefore, we perform (x * inp) + 1.
Since, input can be a maximum 7-degree polynomial. Multiplying by x will only result in x^8 if there is x^7 in input.
Hence, if there is x^7 in input, then (x * inp + 1) will have x^8 and we will need to take mod G(x) of the result.
We know, to find the remainder on dividing by G(x), we can replace x^8 with x^4 + x^3 + x + 1 = (1b) in hex = 27 in decimal.
*/
uchar_t subbyte(uchar_t x){
    uchar_t temp = ((uint16_t) x << 1) ^ 1; //Multiplied input by x and added 1.
    if((x >> 7) & 1) temp ^= 27;    // if there is x^7 in input x, then temp will have x^8, to take remainder from G(x), cor with 27 is done
    uint16_t t2 = temp & 15;    //least significant 4 bits as column number
    uint16_t t1 = temp >> 4;    //most significant 4 bits as row number
    return subbyte_table[t1][t2]; //table look-up
}


/*
Let us try to understand here how are we going to calculate the inverse subbyte.
Suppose the input to our subbyte function was "inp" and its subbyte is "subInp".
Therefore, the input to inverse subbyte function will be "subInp". We will first search this value in the table.
We will concatenate the row and column number where "subInp" will be located. This will give us a 8-bit binary string (say y.)
and actually y = ((x * inp) + 1) mod G(x)

During subbyte, we calculated (x * inp + 1). If we observe carefully, (x * inp + 1) will always have its LSB set (not taken mod G(x))
Now, let's see the two cases:
    Case 1: x^7 bit is not set in input
        In this case we will not xor with 27. Hence, LSB of (x * inp + 1) will be set.
        Also, y = (x * inp + 1) mod G(x) = (x * inp + 1) in this case. Hence, y has LSB set in this case.
        
    Case 2: x^7 bit is set in the input
        In this case, as there will be x^8 in (x * inp + 1), we will xor with 27. 
        Therefore, y = (x * inp + 1) mod G(x) = (x * inp + 1) ^ 27.
        Since, (x * inp + 1) has its LSB set and 27 has also its LSB set. Therefore, y has LSB = 0 in this case.

Now, during inverse we will receive subInp as input from which we calculated y.
Inverse can be calculated using the following two cases:
    Case 1: LSB of y is set
        This corresponds to case 1 above and hence y = (x * inp + 1) here. Hence, we can directly divide y by x, i.e. (y >> 1), 
        here to find the inverse. (we do not need to subtract (xor) 1 as it will be wiped out anyways on right shifting by 1).

    Case 2: LSB of y is not set
        In this case, y = (x * inp + 1) mod G(x) = (x * inp + 1) ^ 27. Therefore, (x * inp + 1) = y ^ 27.
        (Again, subtracting 1 or not doesn't affect as we will divide by x). Therefore, now we can divide 
        (y ^ 27) by x, i.e. ((y ^ 27) >> 1) to get inverse. However, since, we know x^7 bit was set in this case.
        So, we have set it here. Therefore, inverse will be ((y ^ 27) >> 1) | (1 << 7).
*/
uchar_t inverseSubbyte(uchar_t x){
    uchar_t inv = 0;

    //finding x = subInp in the look-up table and calcuating y = inv (as describe above)
    for(uchar_t i = 0; i < 16; i++){
        for(uchar_t j = 0; j < 16; j++){
            if(subbyte_table[i][j] == x){ 
                inv = ((i << 4) | j);
            }
        }
    }

    // cases are described above
    if(inv & 1) inv = inv >> 1;    //case where LSB of inv is set
    else inv = ((inv ^ 27) >> 1) | (1 << 7); //case where LSB of inv is not set

    return inv;
}

//Shift Row function, left circular shifts the i^th row by i positions.
void shiftRow(uchar_t s[4][4]){
    for(int i = 1; i < 4; i++){ //0th row has shift of 0, therefore starting the loop from row 1
        uchar_t temp[4];    
        for(int j = 0; j < 4; j++) temp[j] = s[i][j];  //storing the ith row in temp array
        for(int j = 0; j < 4; j++){
            s[i][j] = temp[(j + i) % 4]; //left circular shifting the row ith by i positions
        }
    }
}

//Inverse Shift Row function, right circular shifts the i^th row by i positions
void invShiftRow(uchar_t s[4][4]){
    for(int i = 1; i < 4; i++){     //0th row has shift of 0, therefore starting the loop from row 1
        uchar_t temp[4];
        for(int j = 0; j < 4; j++) temp[j] = s[i][j];  //storing the ith row in temp array
        for(int j = 0; j < 4; j++){
            s[i][j] = temp[(j + 4 - i) % 4];  //right circular shifting the ith row by i positions
        }
    }
}

//helper function, Input: a polynomial with degree <= 7 (say, input), Output: (x^2 * input) mod G(x)
//we know, to find the remainder obtained from dividing by G(x), we replace x^8 with (x^4 + x^3 + x + 1).
//Since, the input can have a maximum degree of 7, after multiplication with x^2, we can have x^9 as well as x^8 in the result.
//we will simply replace x^8 by xoring with 27 = (0x1b) as done during subbyte function.
// also x^9 can be written as (x * (x^8)), therefore, to replace x^9 we will xor with (x * (x^4 + x^3 + x + 1)) = 54 = (0x36)
uchar_t x2TimesS(uchar_t x){
    uchar_t temp = x << 2; //multiplied by x^2
    if((x >> 6) & 1) temp ^= (0x1b); //checked if there is x^6 in input, it will result in x^8, hence, to get the remainder, xoring with 0x1b
    if(x >> 7) temp ^= (0x36);  //checked if there is x^7 in input, it will result in x^9, hence, to get the remainder, xoring with 0x36
    return temp; 
}

/*
The modified mix column matrix for AES-prime.
 const uchar_t M[4][4] = {
    {0x01, 0x04, 0x04, 0x05},
    {0x05, 0x01, 0x04, 0x04},
    {0x04, 0x05, 0x01, 0x04},
    {0x04, 0x04, 0x05, 0x01}
};

Hex     Polynomial
0x01        1
0x04       x^2
0x05       x^2 + 1

Therefore, we can multiply with x^2 taking mod G(x) as in the function described above.
*/

void mixColumns(uchar_t s[4][4]){
    for(int i = 0; i < 4; i++){ //for each column of input matrix
        //calculating the 4 polynomial according to the mix column matrix
        uchar_t t1 = s[0][i] ^ x2TimesS(s[1][i]) ^ x2TimesS(s[2][i]) ^ x2TimesS(s[3][i]) ^ s[3][i];
        uchar_t t2 = x2TimesS(s[0][i]) ^ s[0][i] ^ s[1][i] ^ x2TimesS(s[2][i]) ^ x2TimesS(s[3][i]);
        uchar_t t3 = x2TimesS(s[0][i]) ^ x2TimesS(s[1][i]) ^ s[1][i] ^ s[2][i] ^ x2TimesS(s[3][i]);
        uchar_t t4 = x2TimesS(s[0][i]) ^ x2TimesS(s[1][i]) ^ x2TimesS(s[2][i]) ^ s[2][i] ^ s[3][i];

        //updating the column of input, with mix column value
        s[0][i] = t1;
        s[1][i] = t2;
        s[2][i] = t3;
        s[3][i] = t4;
    }
}

//function to calculate input modulo G(x), where input is any polynomial of degree <= 15.
uchar_t modGx(uint16_t x){
    for(int i = 15; i > 7; i--){ //loop from 15 to 8, because if x^7 or lower bit is set, then it is already mod G(x)
        if((x >> i) & 1){     //checking if x^i bit is set, i.e, if x^i is in the polynomial
            //now, to calculate modulo, if we have x^8, we replace it with 27. Here,
            //x^i = x^(i-8). x^8, therefore, we will replace x^i with x^(i-8) * 27.
            
            x = x ^ (1 << i);  //we need to replace, so first remove x^i, i.e. make ith bit zero.
            x = x ^ (0x1b << (i - 8)); // now, xor it with x^(i-8) * 27 = (0x1b << (i - 8)).
        }
    }
    return x & 0xff;
}

//the matrix used to calculate the inverse of mix columns in AES-prime
const uchar_t M_inv[4][4] = {
    {0xa5, 0x07, 0x1a, 0x73},
    {0x73, 0xa5, 0x07, 0x1a},
    {0x1a, 0x73, 0xa5, 0x07},
    {0x07, 0x1a, 0x73, 0xa5}
};

void invMixCols(uchar_t s[4][4]){
    uchar_t temp[4]; //stores mix column inverse of a column
    uchar_t z = 0xff;

    //matrix multiplication
    for(uint16_t i = 0; i < 4; i++){
        for(uint16_t j = 0; j < 4; j++){
            uint16_t x = (uint16_t)0;
            for(uint16_t k = 0; k < 4; k++){
                //the product() method does not take modulo with G(x)
                //hence, max degree of x here can be 15. Hence, x is uint16_t.
                uint16_t y =  product(M_inv[j][k], s[k][i]);
                x = x ^ y;
            }
    
            temp[j] = modGx(x); //taking modulo from G(x) and storing it in temp
        }

        for(uint16_t j = 0; j < 4; j++){
            s[j][i] = temp[j]; //updating the input column with its mix column inverse.
        }
    }
}

//function to left circular shift a 32-bit word by 8 bits (or 1 byte)
uint32_t rotWord(uint32_t x){
    uchar_t z = 0xff; 
    uchar_t temp = (x >> 24) & z; //taking out the most significant byte
    // left shifting by 8 bits, here we will lose the most signifcant 8-bits from input (but, stored in temp) which
    //should have come at the least significant 8-bits position in the output.
    //all the least significant 8-bits of (x << 8) will be zero. we will or (x << 8) with temp to get the temp bits at LS byte positon.
    x = (x << 8) | temp; 
    return x;
}

//the original subbyte function of AES-128, its inverse will not be required as key remains the same
//during encryption as well as decryption
uchar_t subbyte_org(uchar_t x){
    uint16_t t2 = x & 15;    //least significant 4 bits as column number
    uint16_t t1 = x >> 4;    //most significant 4 bits as row number
    return subbyte_table[t1][t2]; //table look-up
}


//function to perform subbytes of each byte of the 32-bit word.
//Each word contains 4-bytes and we have to perform subbytes of each of them
uint32_t subWord(uint32_t x){
    uchar_t z = 0xff;
    uchar_t x0, x1, x2, x3; //x = x0 || x1 || x2 || x3, x0, x1, x2, x3 are bytes of the 32-bit word.
    x0 = (x >> 24) & z; 
    x1 = (x >> 16) & z; 
    x2 = (x >> 8) & z;
    x3 = x & z;

    //performing subbyte on each byte, since Key Scheduling uses original subbyte function.
    x0 = subbyte_org(x0);
    x1 = subbyte_org(x1);
    x2 = subbyte_org(x2);
    x3 = subbyte_org(x3);

    //output = subbyte(x0) || subbyte(x1) || subbyte(x2) || subbyte(x3)
    x = (x0 << 24) | (x1 << 16) | (x2 << 8) | x3;
    return x;
}

//this function generates the round keys for AES-prime, and is exactly similar to AES-128
void keyScheduling(uchar_t key[16], uchar_t roundKeys[11][4][4]){
    uint32_t words[44]; //44 words that will be generated will be stored here
    uchar_t z = 0xff;
    for(int i = 0; i < 4; i++){  //the first 4 words are similar to key, i.e, if we concatenate the first 4 words, we will get the key
        words[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | (key[4*i+3]);
    }

    //finding remaining words according to the key scheduling algorithm
    for(int i = 4; i < 44; i++){
        uint32_t temp = words[i-1]; 
        if(i % 4 == 0) temp = subWord(rotWord(temp)) ^ (RCON[i/4 - 1]); //subWord function uses original subbyte function of AES-128
        words[i] = words[i-4] ^ temp;
    }
    
    //the 11 round keys are stored as 4*4 matrix in column-wise manner
    //each roundKey[i] is a round key.
    for(int i = 0; i < 11; i++){
        for(int j = 0; j < 4; j++){
            for(int k = 0; k < 4; k++){
                roundKeys[i][k][j] = (words[4*i+j] >> (24 - 8 * k)) & z; //breaking each word into 4 bytes
            }
        }
    }
}

//the round function f of AES-prime
void roundFunction(int r, uchar_t s[4][4]){
    //the variable r stores which round it is
    // perform subbyte(input)
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s[i][j] = subbyte(s[i][j]);
        }
    }
    //perform shift row
    shiftRow(s);
    //if it is not the last,i.e. 10th round, perform mix columns.
    if(r < 10) mixColumns(s);
}

//the inverse round function f of AES-prime
void inverseRoundFunction(int r, uchar_t s[4][4]){
    //if it is the 10th round, we don't need to to mix column inverse, else we do.
    if(r != 10) invMixCols(s);
    //perform shift row inverse
    invShiftRow(s);
    //perform subbyte inverse
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s[i][j] = inverseSubbyte(s[i][j]);
        }
    }
}

//this function encrypts using the AES-prime algorithm
void encryptAES(uchar_t plaintext[16], uchar_t key[16], uchar_t ciphertext[16]){
    uchar_t s[4][4];
    uchar_t k[4][4];

    //first just store the key and plaintext in 4*4 matrices
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s[j][i] = plaintext[i * 4 + j];
            k[j][i] = key[i * 4 + j];
        }
    }
    
    uchar_t roundKeys[11][4][4];
    keyScheduling(key, roundKeys); //generate roung keys

    //perform encryption
    for(int i = 0; i < 11; i++){
        //first mix the round keys
        for(int j = 0; j < 4; j++){
            for(int x = 0; x < 4; x++){
                s[j][x] = s[j][x] ^ roundKeys[i][j][x];
            }
        }
        
        //then perform the round function, since, there are only 10 rounds, therefore
        //round function is called for 10 times only
        if(i < 10) roundFunction(i+1, s);
        //in the last iteration of the loop, only the last round key is mixed (round function is not called)
    }

    //store the generated ciphertext in a 1-D array.
    int index = 0;
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            ciphertext[index++] = s[j][i];
        }
    }
}

//this function decrypts using the AES-prime algorithm
void decryptAES(uchar_t ciphertext[16], uchar_t key[16], uchar_t decrypted_text[16]){
    uchar_t s[4][4];
    uchar_t k[4][4];

    //first just store the key and ciphertext in 4*4 matrices
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s[j][i] = ciphertext[i * 4 + j];
            k[j][i] = key[i * 4 + j];
        }
    }
    
    uchar_t roundKeys[11][4][4]; 
    keyScheduling(key, roundKeys); //generate round keys

    //perform decryption
    for(int i = 10; i >= 0; i--){
        //first mix the round keys
        for(int j = 0; j < 4; j++){
            for(int x = 0; x < 4; x++){
                s[j][x] = s[j][x] ^ roundKeys[i][j][x];
            }
        }

        //then perform the  inverse round function, since, there are only 10 rounds, therefore
        //inverse round function is called for 10 times only
        if(i > 0) inverseRoundFunction(i, s);
        //in the last iteration of the loop, only the last round key is mixed (inverse round function is not called)
    }

    //store the generated plaintext in a 1-D array
    int index = 0;
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            decrypted_text[index++] = s[j][i];
        }
    }
}

//helper function to print the array
void print(uchar_t s[16]){
    for(int i = 0; i < 16; i++){
        printf("%02x", s[i]);
    }
    printf("\n");
}

int main(){
    
    uchar_t plaintext[20];

    printf("Enter 128-bit plaintext as input (in hexadecimal, each pair of hex digits separated by spaces): ");
    for(int i = 0; i < 16; i++) {
        scanf("%hhx", &plaintext[i]);    //take plaintext as input
    }
 
    uchar_t key[20]; 
    printf("Enter 128-bit key as input (in hexadecimal, each pair of hex digits separated by spaces): ");
    for(int i = 0; i < 16; i++){
        scanf("%hhx", &key[i]); //take key as input
    }
    
    printf("Plaintext: "); //print plaintext
    print(plaintext);
    printf("Key: ");  //print key
    print(key);

    uchar_t ciphertext[16];
    encryptAES(plaintext, key, ciphertext); //generate ciphertext
    
    printf("Ciphertext: ");
    print(ciphertext); //print ciphertext

    uchar_t decrypted_text[16];
    decryptAES(ciphertext, key, decrypted_text); //generate decrypted text
    printf("Decrypted Text: "); //print decrypted text
    print(decrypted_text);

    return 0;
}

//Example Input:
// Plaintext: 81 82 9c a6 d3 81 67 c9 f2 ff 67 8a e0 ed bb 12
// Key: ab 12 8c e9 ba d7 53 26 b0 97 b6 b1 24 39 ac 12