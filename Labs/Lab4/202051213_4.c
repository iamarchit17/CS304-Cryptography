/*
Coded by: Archit Agrawal (202051213)
*/

#include <stdio.h>

//preprocessors
#define uint16_t unsigned short int
#define uint32_t unsigned int
#define uint64_t unsigned long long int
#define uchar_t unsigned char

//defining the curve y^2 = x^3 + ax + b over Zp*
const uint32_t P = 173;
//curve parameters, 
const uint32_t a = 23; 
const uint32_t b = 11;

const uint32_t thetaX = 0; //x co-ordinate of point at infinity
const uint32_t thetaY = 0; //y co-ordinate of point at infinity

//the point alpha that Alice and Bob will mutually decide among themselves for Eliiptic Curve Diffie Hellman Key Exchange. 
uint32_t alpha[2];

//Used in SHA256: array of round constants: (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
uint32_t k[64] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

//the subbyte table used in AES 256
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

//the Initialization Vector used for encryption in CBC mode.
const uchar_t IV[4][4] = {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}};
// the round constants for AES 256
const uint32_t RCON[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

//function to count all the points with integer coordinates in Zp* that lie on the curve y^2 = x^3 + ax + b
uint32_t countPointsOnCurve(){
    uint32_t count = 0; //number of points
    for(uint32_t i = 1; i < P; i++){ //since, x and y will lie between 1 and P-1 (= 173), both inclusive.
        for(uint32_t j = 1; j < P; j++){
            uint32_t lhs = (j * j) % P;  //calculate LHS, i.e. y^2, take modulo P because work has to be done on discrete system
            uint32_t rhs = ((i * i * i) + a * i + b) % P; //calculate RHS, i.e (x^3 + a * x + b) % P
            if(lhs == rhs) count++; //if lhs and rhs are equal, then the point lies on the curve, increase the count
        }
    }

    return count;
}

//function to store all the points with integer coordinates in Zp* that lie on the curve y^2 = x^3 + ax + b
void pointsOnCurve(uint32_t totalPoints, uint32_t points[totalPoints][2]){
    uint32_t idx = 0;
    for(uint32_t i = 1; i < P; i++){ //since, x and y will lie between 1 and P-1 (= 173), both inclusive.
        for(uint32_t j = 1; j < P; j++){
            uint32_t lhs = (j * j) % P; //calculate LHS, i.e. y^2, take modulo P because work has to be done on discrete system
            uint32_t rhs = ((i * i * i) + a * i + b) % P; //calculate RHS, i.e (x^3 + a * x + b) % P
            if(lhs == rhs) { //if lhs and rhs are equal, then the point lies on the curve, store the point
                points[idx][0] = i;
                points[idx][1] = j;
                idx++;
            }
        }
    }
}

//extended euclidean algorithm to find the multiplicative inverse of 'a' under modulo 'b'
int extendedEuclidean(int a, int b, int* p, int* q){
    if(a == 0){
        *p = 0;
        *q = 1;
        return b;
    }

    int p1, q1;
    int gcd = extendedEuclidean(b % a, a, &p1, &q1);

    *p = q1 - (b/a) * p1;
    *q = p1;

    return gcd;
}

//in case extended euclidean returns a negative multiplicative inverse, we need to make it positive as we require positive numbers only
uint32_t makeInversePositive(int a){
    while(a < 0) a += P;
    return (uint32_t) (a % P);
}

//function to add two points on the curve y^2 = x^3 + ax + b
//we are assuming that it will not get an invalid input
void addPoints(uint32_t p1[2], uint32_t p2[2], uint32_t p3[2]){
    //adding points p1 (x1, y1) and p2(x2, y2) and storing the result in p3(x3, y3)
    //the computation are done in Zp*, therefore -x means additive inverse of x, i.e., P-x
    //and a/b means a * b^(-1), where b^(-1) is multiplicative inverse of b under P.

    uint32_t m; //the value of the slope will be stored here
    if(p1[0] == 0 || p2[0] == 0){ //case where one point is point at infinity (0, 0), and other point is a valid point on curve, result will be the valid point
        if(p1[0] == 0){   //if p1 is 0, p3 = p2
            p3[0] = p2[0];
            p3[1] = p2[1];
        } else {          //else p3 = p1
            p3[0] = p1[0];
            p3[1] = p1[1];
        }
        return; //return because the point sum is calculated
    } else if ((p1[0] == p2[0]) && (p1[1] == P - p2[1])){ //case where x-coordinate is same, but y co-ordinate is additive inverse of each other
        //the result in this case is point at infinity
        p3[0] = thetaX;
        p3[1] = thetaY;
        return;  //return because the point sum is calculated
    } else if ((p1[0] == p2[0]) && (p1[1] == p2[1])) { //case where both points are same
        //using derivation we know that slope at the point is (3 * x1 * x1 + a) / (2 * y1)
        m = (3 * p1[0] * p1[0] + a) % P;   //storing the numerator in m, taking mod P as we need to work on Zp*
        int p, q;
        extendedEuclidean(2 * p1[1], P, &p, &q); //calculationg inverse of (2 * y1) under modulo P
        m = (m * makeInversePositive(p)) % P; // updating m with m = (3 * x1 * x1 + a) * inverse((2 * y1) under mod P)
        //the point sum is yet to be calcuated, hence, do not return
    } else { //case where both the coordinates of the two points are different
        //slope can be calculated as m = (y2 - y1) / (x2 - x1)
        uint32_t numerator = (p2[1] + P - p1[1]) % P;   // calculating (y2 - y1), under mod P
        uint32_t denominator = (p2[0] + P - p1[0]) % P;  // calculating (x2 - x1), under mod P
        int p = 0, q = 0;
        extendedEuclidean(denominator, P, &p, &q); //finding inverse of (x2 - x1) under modulo P
        m = (numerator * makeInversePositive(p)) % P; //updating m = (y2 - y1) * inverse((x2 - x1) under mod P)
        //the point sum is yet to be calcuated, hence, do not return
    }
    
    //calculating the point sum for the last two cases
    p3[0] = (m * m + (P - p1[0]) + (P - p2[0])) % P; // x3 = m*m - x1 - x2
    p3[1] = P - ((p1[1] + m * (p3[0] + P - p1[0])) % P); //y3 = y1 + m * (x3 - x1)
}

//function to compute n times a point on the curve
//similar to the square and multiply algorithm for integers
void pointTimesN(uint32_t n, uint32_t point[2], uint32_t result[2]){
    //point is the Point X, for which we need to compute n.X
    //the product will be stored in result which is initialised with point at infinity
    
    result[0] = thetaX;
    result[1] = thetaY;
    uint32_t temp[2] = {point[0], point[1]}; //temp point
    //computes n.X in log(n) complexity
    //convert n to binary, starting from LSB, if it is 1 do => result = result + temp, 
    //update temp = temp + temp
    //move to next bit of n
    //repeat until n > 0
    
    while(n > 0){
        if(n & 1){      //checking if bit is set or not, if set we need to perform the computation as stated above
            uint32_t t[2]; //to store the summation (result + temp) on EC
            addPoints(result, temp, t);  //finding (result + temp) 
            result[0] = t[0]; //storing it in 'result' as final sum is stored in 'result'
            result[1] = t[1];
        }

        uint32_t t[2]; //updata temp = 2 * temp
        addPoints(temp, temp, t);
        temp[0] = t[0];
        temp[1] = t[1];
        n = n >> 1; //moving to next bit of n
    }
}

//function to right rotate an integer by 'bits' bits
uint32_t rightRotate(uint32_t x, uint32_t bits){
    return ((x >> bits) | (x << (32 - bits)));
}

//function to find the length of message after padding using SHA256 rules
uint32_t paddedLength(uint32_t l){
    //here length l is in terms of words, i.e., a message of length 2l is actually 64 bit message.
    uint32_t x = 0; //number of blocks that will be there in the padded message
    //first, calculate the blocks present in the original message
    //since, block size is 512 bits, therefore 16 words make a block
    if(l % 16 == 0) x = l/16;   //if length is a multiple of 16, then blocks will be l/16
    else x = l/16 + 1;          //otherwise, it will be l/16 + 1. For example, l = 17, then blocks will be 2
    
    //if the condition written below holds, then padding will increase a block, hence x is incremented.
    if(l % 16 == 14 || l % 16 == 15 || l % 16 == 0) x++; 

    return x * 16; //number of words in padded message
}

//perform SHA256 hashing
//Assumptions:
// -> the length of the original message will be lesser than 2^32 - 1.
// -> the message will be a concatenation of words, i.e, 32 bits. This means that you can not enter a message 0x1.
// 0x01 will essentially be treated as 0x00000001. 
//Here, we required only to work on words, that is why, a more generalised SHA256 (that might accept a concatenation of bytes) is not required.

// ****Note****: The hashing is done just as is done in SHA256, so if the input is according to above assumptions, the output will be correct.

void SHA256(uint32_t length, uint32_t m[length], uint32_t hash[8]){
    //message of 'length' words

    //padding is done in SHA256 independent of the fact that the original message meets length requirements or not
    uint32_t paddedLen = paddedLength(length); //find length of padded message, in terms of 32-bit words
    uint32_t paddedMsg[paddedLen]; //padded message
    for(uint32_t i = 0; i < paddedLen; i++) paddedMsg[i] = 0; //initialise to 0, this also sets the padding bits which were to be set as 0.
    
    for(uint32_t i = 0; i < length; i++) paddedMsg[i] = m[i]; //copy the message entirely in padded message
    paddedMsg[length] = ((uint32_t) 1) << 31; //set the just next bit where the original message is completed
    //In SHA256, the length of original message is stored in last 64 bits of the padded message
    //Since, our assumption was that the length of original message is less than 2^32 - 1. It can be stored in last 32 bits only.
    paddedMsg[paddedLen - 1] = 32 * length;  //hence, last word (32 bits) of padded message is the length of original message.
    
    
    //Initialize hash values: (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;


    for(uint32_t j = 0; j < paddedLen/16; j++){ //run this loop for each chunk or block (512 bits) of the padded message.

        uint32_t words[64] = {0}; //the generated 64 words during each loop will be stored here

        for(uint32_t i = 0; i < 16; i++) words[i] = paddedMsg[16 * j + i]; //copy the chunk in first 16 words

        for(uint32_t i = 16; i < 64; i++){ //algorithm to compute remaining words
            uint32_t x = rightRotate(words[i - 15], 7) ^ rightRotate(words[i - 15], 18) ^ (words[i - 15] >> 3); 
            uint32_t y = rightRotate(words[i - 2], 17) ^ rightRotate(words[i - 2], 19) ^ (words[i - 2] >> 10);
            words[i] = words[i - 16] + x + words[i - 7] + y;
        }

        //Initialize working variables to current hash value:
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

        //compression function
        for(uint32_t i = 0; i < 64; i++){
            uint32_t x = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + x + ch + k[i] + words[i];
            uint32_t y = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = y + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        //add compresses chunk to the current hash value
        //the additions here are modulo 2^32.
        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
        h5 = h5 + f;
        h6 = h6 + g;
        h7 = h7 + h;
    }

    //the final hash after processing all the chunks of the message
    hash[0] = h0;
    hash[1] = h1;
    hash[2] = h2;
    hash[3] = h3;
    hash[4] = h4;
    hash[5] = h5;
    hash[6] = h6;
    hash[7] = h7;
}

//helper function to convert a array of unsigned integers to array of unsigned characters
//for example: 0x12345678 => 0x12 0x34 0x56 0x78
void convertToChar(uint32_t hash[8], uchar_t key[32]){
    uchar_t z = 0xff; //mask
    for(uint32_t i = 0; i < 8; i++){ //for each integer in integer array, convert it into 4 succesive characters on char array
        key[i * 4] = hash[i] >> 24;  //1 to 8 bits from left
        key[i * 4 + 1] = (hash[i] >> 16) & z; // 9 to 16 bits from left
        key[i * 4 + 2] = (hash[i] >> 8) & z; // 17 to 24 bits from left
        key[i * 4 + 3] = hash[i] & z; // 25 to 32 bits from left
    }
}

//helper function to convert a array of unsigned characters to array of unsigned integers
//for example: 0x12 0x34 0x56 0x78 => 0x12345678 
void convertToInt(uchar_t x[32], uint32_t y[8]){
    for(int i = 0; i < 8; i++){ //for 4 continuous characters in unsigned char array, convert them to unsigned integer
        uint32_t x1 = x[4 * i];   //these will become first 8 bits from left (shift left by 24)
        uint32_t x2 = x[4 * i + 1]; //these will become bits 9 to 16 from left (shift left by 16)
        uint32_t x3 = x[4 * i + 2]; //these will become bits 17 to 24 from left (shift left by 8)
        uint32_t x4 = x[4 * i + 3]; //these will become last 8 bits from left

        y[i] = (x1 << 24) | (x2 << 16) | (x3 << 8) | x4;
    }
}

//function to generate the MAC as described in the assignment,
//MAC = SHA256((key ^ 1) concat (SHA256((key ^ 2) concat M))) 
void generateMAC(uint32_t key[8], uchar_t M[32], uint32_t MAC[8]){
    //MAC stores the final MAC

    uint32_t inp[16]; //input stores input to the SHA256 function
    //initial inp stores (key ^ 2) || M
    for(uint32_t i = 0; i < 7; i++){ //storing (key ^ 2) in first 8 words of inp
        inp[i] = key[i];
    }
    inp[7] = key[7] ^ 2;
    
    uint32_t convertedM[8]; //the M received here is a character matrix, but SHA receives input as array of words
    convertToInt(M, convertedM); //hence, we converted M from char array to unsigned integer array 'convertedM'
    
    for(uint32_t i = 8; i < 16; i++){
        inp[i] = convertedM[i - 8]; //storing convertedM in last 8 words of inp
    }
    
    uint32_t mac1[8]; //mac1 stores SHA256((key ^ 2) concat M)
    SHA256(16, inp, mac1); //calling the SHA256 function
    
    //now, inp will be storing (key ^ 1) concat (SHA256((key ^ 2) concat M)) = (key ^ 1) concat (mac1)
    for(uint32_t i = 0; i < 7; i++){ //storing (key ^ 1) in first 8 words of inp
        inp[i] = key[i];
    }
    inp[7] = key[7] ^ 1;
    for(uint32_t i = 8; i < 16; i++) inp[i] = mac1[i - 8]; //storing mac1 in last 8 words of inp
    
    SHA256(16, inp, MAC); //after this call to SHA256, MAC will be equal to = SHA256((key ^ 1) concat (SHA256((key ^ 2) concat M)))
}

//the subbyte function of AES-256
uchar_t subbyte(uchar_t x){
    uint16_t t2 = x & 15; //least significant 4 bits as column number
    uint16_t t1 = x >> 4; //most significant 4 bits as row number
    return subbyte_table[t1][t2];  //table look-up
}

//inverse of Subbyte function used in AES-256
uchar_t inverseSubbyte(uchar_t x){
    uchar_t inv = 0;
    //find the value in the table, suppose it is at row i, column j, then inverse will be ((i << 4) | j)
    for(uchar_t i = 0; i < 16; i++){
        for(uchar_t j = 0; j < 16; j++){
            if(subbyte_table[i][j] == x){ //if found at row i and column j
                return ((i << 4) | j); //return ((i << 4) | j)
            }
        }
    }
    return 0;
}

//Shift Row function of AES-256, left circular shifts the i^th row by i positions.
void shiftRow(uchar_t s[4][4]){
    for(int i = 1; i < 4; i++){ //0th row has shift of 0, therefore starting the loop from row 1
        uchar_t temp[4];
        for(int j = 0; j < 4; j++) temp[j] = s[i][j]; //storing the ith row in temp array
        for(int j = 0; j < 4; j++){
            s[i][j] = temp[(j + i) % 4]; //left circular shifting the row ith by i positions
        }
    }
}

//Inverse Shift Row Function of AES-256, right circular shifts the i^th row by i positions
void invShiftRow(uchar_t s[4][4]){
    for(int i = 1; i < 4; i++){ //0th row has shift of 0, therefore starting the loop from row 1
        uchar_t temp[4];
        for(int j = 0; j < 4; j++) temp[j] = s[i][j]; //storing the ith row in temp array
        for(int j = 0; j < 4; j++){
            s[i][j] = temp[(j + 4 - i) % 4]; //right circular shifting the ith row by i positions
        }
    }
}

//function to perform a polynomial multiplication of polynomial with x under modulo x^8 + x^4 + x^3 + x + 1
//the polynomial to be multiplied with x, is represeted as a binary byte 'x'
uchar_t xTimesS(uchar_t x){
    uchar_t temp = x << 1; //multiplied the polynomial by x
    //if the polynomial has x^7, then on multiplying by x, it becomes x^8, to take modulus with
    //x^8 + x^4 + x^3 + x + 1, we need replace x^8 with x^4 + x^3 + x + 1, 
    //computationally it is equivalent to xoring in with (0x1b)
    if(x >> 7) temp = temp ^ (0x1b); 
    return temp;
}

/*
The modified mix column matrix for AES-prime.
 const uchar_t M[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};

Hex     Polynomial
0x01        1
0x02        x
0x03      x + 1

Therefore, we can multiply with x taking mod G(x) as in the function described above.
*/

//Mix Columns function of AES-256
void mixColumns(uchar_t s[4][4]){
    for(int i = 0; i < 4; i++){ //for each column of input matrix
        //calculating the 4 polynomial according to the mix column matrix
        uchar_t t1 = xTimesS(s[0][i]) ^ xTimesS(s[1][i]) ^ s[1][i] ^ s[2][i] ^ s[3][i];
        uchar_t t2 = s[0][i] ^ xTimesS(s[1][i]) ^ xTimesS(s[2][i]) ^ s[2][i] ^ s[3][i];
        uchar_t t3 = s[0][i] ^ s[1][i] ^ xTimesS(s[2][i]) ^ xTimesS(s[3][i]) ^ s[3][i];
        uchar_t t4 = xTimesS(s[0][i]) ^ s[0][i] ^ s[1][i] ^ s[2][i] ^ xTimesS(s[3][i]);
        //updating the column of input, with mix column value
        s[0][i] = t1;
        s[1][i] = t2;
        s[2][i] = t3;
        s[3][i] = t4;
    }
}

//Inverse Mix Columns Function of AES-256
void invMixCols(uchar_t s[4][4]){
    //it has been proved that M^4 * S = I
    //therefore inverse of M is M^3
    mixColumns(s); 
    mixColumns(s);
    mixColumns(s);
}

//function to left circular shift a 32-bit word by 8 bits (or 1 byte)
uint32_t rotWord(uint32_t x){
    uchar_t z = 0xff;
    uchar_t temp = (x >> 24) & z;    //taking out the most significant byte
    // left shifting by 8 bits, here we will lose the most signifcant 8-bits from input (but, stored in temp) which
    //should have come at the least significant 8-bits position in the output.
    //all the least significant 8-bits of (x << 8) will be zero. we will or (x << 8) with temp to get the temp bits at LS byte positon.
    x = (x << 8) | temp;
    return x;
}

//function to perform subbytes of each byte of the 32-bit word.
//Each word contains 4-bytes and we have to perform subbytes of each of them
uint32_t subWord(uint32_t x){
    uchar_t z = 0xff;
    uchar_t x0, x1, x2, x3;  //x = x0 || x1 || x2 || x3, x0, x1, x2, x3 are bytes of the 32-bit word.
    x0 = (x >> 24) & z;
    x1 = (x >> 16) & z;
    x2 = (x >> 8) & z;
    x3 = x & z;
    //performing subbyte on each byte, since Key Scheduling uses original subbyte function.
    x0 = subbyte(x0);
    x1 = subbyte(x1);
    x2 = subbyte(x2);
    x3 = subbyte(x3);
    //output = subbyte(x0) || subbyte(x1) || subbyte(x2) || subbyte(x3)
    x = (x0 << 24) | (x1 << 16) | (x2 << 8) | x3;
    return x;
}

//this function generates the round keys for AES-256
void keyScheduling(uchar_t key[32], uchar_t roundKeys[15][4][4]){

    
    uint32_t words[60];   //60 words that will be generated will be stored here
    uchar_t z = 0xff;

    for(int i = 0; i < 8; i++){  //the first 8 words are similar to key, i.e, if we concatenate the first 8 words, we will get the key
        words[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | (key[4*i+3]);
    }

    //finding remaining words according to the key scheduling algorithm
    for(int i = 8; i < 60; i++){
        uint32_t temp = words[i-1];
        if(i % 8 == 0) temp = subWord(rotWord(temp)) ^ (RCON[i/8 - 1]);
        else if(i % 8 == 4) temp = subWord(temp);
        words[i] = words[i - 8] ^ temp;
    }
    
    //the 15 round keys are stored as 4*4 matrix in column-wise manner
    //each roundKey[i] is a round key.
    for(int i = 0; i < 15; i++){
        for(int j = 0; j < 4; j++){
            for(int k = 0; k < 4; k++){
                roundKeys[i][k][j] = (words[4*i+j] >> (24 - 8 * k)) & z;  //breaking each word into 4 bytes
            }
        }
    }
}

//the round function f of AES-256
void roundFunction(int round, uchar_t s[4][4]){
    //the variable round stores which round it is
    // perform subbyte(input)
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s[i][j] = subbyte(s[i][j]);
        }
    }
    //perform shift row
    shiftRow(s);
    //if it is not the last,i.e. 14th round, perform mix columns.
    if(round < 14) mixColumns(s);
}

//the inverse round function f^-1 of AES-256
void inverseRoundFunction(int round, uchar_t s[4][4]){
    //if it is the 14th round, we don't need to to mix column inverse, else we do.
    if(round != 14) invMixCols(s);
    //perform shift row inverse
    invShiftRow(s);
    //perform subbyte inverse
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s[i][j] = inverseSubbyte(s[i][j]);
        }
    }
}

//function to encrypt plaintext using AES-256 in CBC mode
void encryptAES(int length, uchar_t plaintext[length], uchar_t key[32], uchar_t ciphertext[length + 16]){
    //length here is number bytes (8 bit) in the plaintext
    //since AES-256 can encrypt 128 bit data at a time, it means that length of a block is 16, as 16 * 8 = 128
    //in CBC mode, the first ciphertext block is the IV, therefore ciphertext has n+1 blocks if plaintext has n blocks

    uint32_t index = 0; //this stores the current index available to put data in the ciphertext
    
    uchar_t roundKeys[15][4][4];  //stores the round keys
    keyScheduling(key, roundKeys); //generating the round keys
    int blocks = length/16;  //finding number of blocks in the plaintext
    
    //this stores the ciphertext corresponding to last block, 
    //as in CBC mode, it is xored with the ciphertext corresponding to current block
    //initially it is equal to the IV
    uchar_t fedBackCBC[4][4];
    for(uchar_t i = 0; i < 4; i++){
        for(uchar_t j = 0; j < 4; j++){
            fedBackCBC[i][j] = IV[i][j]; //storing IV in the fedBackCBC
            ciphertext[index++] = IV[i][j]; //since first block of ciphertext is the IV itself
        }
    }
    
    for(uint32_t k = 0; k < blocks; k++){ //encrypting each block of plaintext sequentially
        
        uchar_t s[4][4]; //stores plaintext corresponding to current block
        
        for(uint32_t i = 0; i < 4; i++){
            for(uint32_t j = 0; j < 4; j++){
                s[j][i] = plaintext[k * 16 + i * 4 + j]; //storing the current block of plaintext in s
            }
        }
        
        for(uint32_t i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                s[i][j] = s[i][j] ^ fedBackCBC[i][j]; //xoring current block's plaintext with previous block's ciphertext (IV for the very first block)
            }
        }
        
        //perform encryption
        for(uint32_t i = 0; i < 15; i++){
            for(uint32_t j = 0; j < 4; j++){
                for(uint32_t x = 0; x < 4; x++){
                    s[j][x] = s[j][x] ^ roundKeys[i][j][x]; //adding the key
                }
            }
            
            if(i < 14) roundFunction(i+1, s); //calling round functions
            //in the last iteration of the loop, only the last round key is mixed (round function is not called)
        }
        
        //store the generated ciphertext in the ciphertext (as it is ciphertext) and also in fedBackCBC (as it will be required for encrypting next block)
        for(uint32_t i = 0; i < 4; i++){
            for(uint32_t j = 0; j < 4; j++){
                fedBackCBC[i][j] = s[i][j]; //storing current block's ciphertext in fedBackCBC
                ciphertext[index++] = s[j][i]; //storing current block's ciphertext it in ciphertext
            }
        }
    }
}

//function to decrypt ciphertext using AES-256 in CBC mode
void decryptAES(uchar_t length, uchar_t ciphertext[length], uchar_t key[32], uchar_t decrypted_text[length - 16]){
    //length here is number bytes (8 bit) in the ciphertext
    //since AES-256 can encrypt 128 bit data at a time, it means that length of a block is 16, as 16 * 8 = 128
    //in CBC mode, the first ciphertext block is the IV, therefore ciphertext has n+1 blocks if plaintext has n blocks
    //therefore, decrypted text will have n blocks, if ciphertext has n+1 blocks

    int index = 0; //this stores the current index available to put data in the plaintext
    
    uchar_t roundKeys[15][4][4];   //stores the round keys
    keyScheduling(key, roundKeys);  //generating the round keys
    uint32_t blocks = length/16 - 1;  //finding number of blocks in the plaintext (that's why a -1 is there)

    uchar_t decryptFedBack[4][4]; //this stores the ciphertext corresponding to last block, 
    //as in CBC mode, it is xored with the decrypted text corresponding to current block to get the original plaintext block
    //initially it is equal to the IV

    //since first block of ciphertext is essentially the IV, therefore decryption begins from 2nd block

    for(uint32_t k = 0; k < blocks; k++){
        uchar_t s[4][4]; //stores ciphertext corresponding to current block
        
        for(uint32_t i = 0; i < 4; i++){
            for(uint32_t j = 0; j < 4; j++){
                s[j][i] = ciphertext[((k + 1) * 16) + i * 4 + j];  //storing the current block of ciphertext in s
            }
        }
        
        for(uint32_t i = 0; i < 4; i++){
            for(uint32_t j = 0; j < 4; j++){
                decryptFedBack[j][i] = ciphertext[k * 16 + i * 4 + j]; //storing previous block of ciphertext in 'decryptedFedBack'
            }
        }
        
        //performing decryption
        for(int i = 14; i >= 0; i--){
            //first mix the round keys
            for(uint32_t j = 0; j < 4; j++){
                for(uint32_t x = 0; x < 4; x++){
                    s[j][x] = s[j][x] ^ roundKeys[i][j][x];
                }
            }
            //then perform the  inverse round function, since, there are only 14 rounds, therefore
            //inverse round function is called for 14 times only
            if(i > 0) inverseRoundFunction(i, s);
            //in the last iteration of the loop, only the last round key is mixed (inverse round function is not called)
        }
        
        for(uint32_t i = 0; i < 4; i++){
            for(uint32_t j = 0; j < 4; j++){
                s[i][j] = s[i][j] ^ decryptFedBack[i][j]; //mix the decrypted text with previous block's ciphertext to get original plaintext block
            }
        }
        
        for(uint32_t i = 0; i < 4; i++){
            for(uint32_t j = 0; j < 4; j++){
                decrypted_text[index++] = s[j][i]; //storing original plaintext in the decrypted_text array
            }
        }
    }
}

//helper function to print an unsigned character array of length 'length'
void print(uint32_t length, uchar_t s[length]){
    for(int i = 0; i < length; i++){
        printf("%02x ", s[i]);
    }
    printf("\n");
}

int main(){
    printf("\n");
    
    //count total number of points with integer coordinates in Zp* lie on the curve y^2 = x^3 + 23*x + 11
    int totalPoints = countPointsOnCurve(); 
    //create an array for storing all the points
    uint32_t points[totalPoints][2];
    //find and store all the points in the array
    pointsOnCurve(totalPoints, points);

    uint32_t idx; //take input idx to find the point alpha
    printf("Enter a number between 1 and %d (both inclusive) to get the point alpha: ", totalPoints);
    //this do-while loop takes input and makes sure that the user enters the data in the given range only
    do{
        scanf("%u", &idx);
        if(idx < 1 || idx > totalPoints){
            printf("Error, enter a number in the given range.\n");
            printf("Enter a number between 1 and %d (both inclusive) to get the point alpha: ", totalPoints);
        }
    } while(idx > totalPoints || idx < 1);

    //the point alpha
    alpha[0] = points[idx - 1][0];
    alpha[1] = points[idx - 1][1];

    printf("The point alpha is: (%u, %u)\n", alpha[0], alpha[1]);
    printf("\n");

    uint32_t nA, nB; //take Alice's and Bob's private key as input
    printf("Enter Alice's Private Key (an integer between 1 and 150 (both inclusive)): ");
    //this do-while loop takes input and makes sure that the user enters the data in the given range only
    do{
        scanf("%u", &nA);
        if(nA < 1 || nA > 150){
            printf("Error, enter a number in the given range.\n");
            printf("Enter Alice's Private Key (an integer between 1 and 150 (both inclusive)): ");
        }
    } while(nA > 150 || nA < 1);

    printf("Enter Bob's Private Key (an integer between 1 and 150 (both inclusive)): ");
    //this do-while loop takes input and makes sure that the user enters the data in the given range only
    do{
        scanf("%u", &nB);
        if(nB < 1 || nB > 150){
            printf("Error, enter a number in the given range.\n");
            printf("Enter Alice's Private Key (an integer between 1 and 150 (both inclusive)): ");
        }
    } while(nB > 150 || nB < 1); 

    //computing Alice's public key and storing it in 'naAlpha'
    uint32_t naAlpha[2];
    pointTimesN(nA, alpha, naAlpha);

    //computing Bob's public key and storing it in 'nbAlpha'
    uint32_t nbAlpha[2];
    pointTimesN(nB, alpha, nbAlpha);

    //Alice and Bob have exchanged their public keys and are now computing the shared secret key for the communication...

    uint32_t naNbAlpha[2]; //the shared secret key computed by Alice 
    uint32_t nbNaAlpha[2]; //the shared secret key computed by Bob
    //essentially naNbAlpha = nbNaAlpha
    pointTimesN(nA, nbAlpha, naNbAlpha);
    pointTimesN(nB, naAlpha, nbNaAlpha);
    printf("\n");

    //printing the shared secret key
    printf("The Shared Secret key between Alice and Bob is: (%u, %u)\n", nbNaAlpha[0], nbNaAlpha[1]);

    uint32_t kA[8] = {0}; //hash of key of Alice
    //the input to hash is (x1 concat y1) where x1 and y1 are coordinates of shared secret key that Alice holds
    //(it will be same as the key that Alice holds unless there is some attack or some noise or some data loss in their connection)
    //since x1 and y1 are each 32 bits, therefore, the message to be hashed is of 64 bits.
    uint32_t msgA[2] = {naNbAlpha[0], naNbAlpha[1]}; 
    
    SHA256(2, msgA, kA); //finding kA = SHA256(msgA)
    
    uint32_t kB[8] = {0};  //hash of key of Bob
    //the input to hash is (x1 concat y1) where x1 and y1 are coordinates of shared secret key that Bob holds
    //(it will be same as the key that Bob holds unless there is some attack or some noise or some data loss in their connection)
    //since x1 and y1 are each 32 bits, therefore, the message to be hashed is of 64 bits.
    uint32_t msgB[2] = {nbNaAlpha[0], nbNaAlpha[1]};

    SHA256(2, msgB, kB); //finding kB = SHA256(msgB)

    printf("\n");
    printf("kA: ");
    for(int i = 0; i < 8; i++) printf("%08x ", kA[i]);
    
    printf("\n");

    printf("kB: ");
    for(int i = 0; i < 8; i++) printf("%08x ", kB[i]);

    printf("\n\n");

    //taking the message that Alice will encrypt as input
    uchar_t MA[32];
    printf("Enter 256-bit message of Alice (in hexadecimal, each pair of hex digits separated by spaces): ");
    for(int i = 0; i < 32; i++) {
        scanf("%hhx", &MA[i]);    
    }

    printf("\n");
    printf("mA: ");
    print(32, MA);
    
    //encrypting the message using Alice's shared secret key
    //the shared secret key of Alice is stored in kA as concatenation of unsigned integers
    //to perform AES-256 encryption, we need to convert the key as concatenation of unsigned chars
    uchar_t keyA[32]; //kA as unsigned chars
    convertToChar(kA, keyA);
    uchar_t CA[48]; //ciphertext corresponding to Alice's text
    //since, plaintext length is fixed in the assignment (32 * 8 = 256 bits), therefore the ciphertext will be 48 * 8 = 384 bits
    encryptAES(32, MA, keyA, CA);
    printf("cA: ");
    print(48, CA); 

    uint32_t macA[8]; //stores mac for the message MA computed by Alice using kA
    generateMAC(kA, MA, macA);
    
    printf("macA: ");
    for(int i = 0; i < 8; i++){
        printf("%08x ", macA[i]);
    }
    printf("\n\n");

    //Alice now transfers the ciphertext CA, mac MA and IV to Bob

    uchar_t keyB[32]; //conveting Bob's shared secret key to unsigned char
    convertToChar(kB, keyB);
    uchar_t MB[32]; //bob decrypts CA using his key keyB and stores it in MB
    decryptAES(48, CA, keyB, MB);
    printf("mB: ");
    print(32, MB);

    uint32_t macB[8]; //from MB, Bob computes macB for the message MB using kB
    generateMAC(kB, MB, macB);
    
    printf("macB: ");
    for(int i = 0; i < 8; i++){
        printf("%08x ", macB[i]);
    }
    
    return 0;
}

// Example Plaintext: 81 82 9c a6 d3 81 67 c9 f2 ff 67 8a e0 ed bb 12 ab 12 8c e9 ba d7 53 26 b0 97 b6 b1 24 39 ac 12

//81829ca6d38167c9f2ff678ae0edbb12ab128ce9bad75326b097b6b12439ac12



//Ka = SHA256(na nb alpha)  --> (x, y) ---> SHA256(x || y)
//Kb = SHA256(nb na alpha)