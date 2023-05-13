//Archit Agrawal
//202051213

#include<stdio.h>
#define uint16_t unsigned short int
#define uint32_t unsigned long int
#define uint64_t unsigned long long int

//the given substitution box in question, represented as array
//it means that if value is 0, it will be replaced by 14. If it is 1, it will be replaced by 4.
int substitutionBox[] = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7};

//permutation box as given in question, represented as array.
//It means the 1st bit will move to 1st bit in output, the 2nd bit will move to 5th bit in output and so on.
//The bits are taken from ith position and put at the mentioned position from MSB side.
int permutationBox[] = {1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16};

//the inverse of the substitution box given in the question, required for decryption.
int inverseSubBox[] = {14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5};

//the inverse of permutation box is also required, but it is same as the permutation box itself. hence, not written explicitly


//a function that performs substitution during encryption process
uint16_t substitution(uint16_t plaintext){
    uint16_t substituted;  //stores the output

    //plaintext --> x0x1x2.....x15
    uint16_t x1 = plaintext & 15; //the 4 LSB of plaintext (x12x13x14x15)
    uint16_t x2 = (plaintext >> 4) & 15; // (x8x9x10x11)
    uint16_t x3 = (plaintext >> 8) & 15; // (x4x5x6x7)
    uint16_t x4 = (plaintext >> 12) & 15; // 4 MSB of plaintext (x0x1x2x3)

    //printf("%x %x %x %x", x1, x2, x3, x4);
    //substituting the values using substitution box
    x1 = substitutionBox[x1]; 
    x2 = substitutionBox[x2];
    x3 = substitutionBox[x3];
    x4 = substitutionBox[x4];

    //printf("%x %x %x %x", x1, x2, x3, x4);

    //forming the output
    substituted = (x4 << 12) | (x3 << 8) | (x2 << 4) | x1;

    //printf("%x", substituted);
    return substituted;
}

//a function that performs substitution during decryption process
uint16_t inverseSubstitution(uint16_t ciphertext){
    uint16_t substituted; //stores the output

    //ciphertext --> c0c1c2c3....c15
    uint16_t x1 = ciphertext & 15; //the 4 LSB of ciphertext (c12c13c14c15)
    uint16_t x2 = (ciphertext >> 4) & 15; //(c8c9c10c11)
    uint16_t x3 = (ciphertext >> 8) & 15; //(c4c5c6c7)
    uint16_t x4 = (ciphertext >> 12) & 15; //4 MSB of ciphertext (c0c1c2c3)

    //printf("%x %x %x %x", x1, x2, x3, x4);
    x1 = inverseSubBox[x1];
    x2 = inverseSubBox[x2];
    x3 = inverseSubBox[x3];
    x4 = inverseSubBox[x4];

    //printf("%x %x %x %x", x1, x2, x3, x4);
    //forming the output
    substituted = (x4 << 12) | (x3 << 8) | (x2 << 4) | x1;

    //printf("%x", substituted);
    return substituted;
}

//function to perform permutation during both encryption and decryption
uint16_t permutation(uint16_t plaintext){
    uint16_t x = 1; //helper variable
    uint16_t permuted; //stores the output

    for(int i = 0; i < 16; i++){
        uint16_t bit = permutationBox[i] - 1; //stores which bit to extract from MSB side
        //If ith bit from MSB is to be extracted, that mean (15-i)th bit to be extracted from LSB
        //we cant extract it by right shifting plaintext by (15-bit) times and taking & with 1.
        uint16_t y = (plaintext >> (15 - bit)) & x; //extracts the bit

        //we have to put this bit at ith position from MSB
        //this is done as left shifting the permuted by 1 and then doing | with y. The bits will keep shifting 
        //and at the end the bit y will move to desired position in permuted
        permuted = (permuted << 1) | y; 
    }
    return permuted;
}

//function to generate the round keys from the given key
void generateRoundKeys(uint32_t key, uint16_t roundKeys[5]){
    uint16_t m = 0;
    //key is 32 bit
    //we can extract any 16 bits, by bringing them to LSB, and taking & with (ffff)
    for(int i = 0; i < 5; i++){
        int x = 4 * (i + 1) - 3; //getting the value of 4*r - 3
        //to shift the required 16 bits on LSB, we need to right shift key by y bits
        int y = 32 - (x + 15); 
        roundKeys[i] = (key >> y) & (~m); //getting the round key by performing &
    }
}

//function to encrypt given text using the SPN given
uint16_t encryption(uint16_t plaintext, uint32_t key){
    uint16_t ciphertext = plaintext;

    uint16_t roundKeys[5];
    generateRoundKeys(key, roundKeys); //generating the round keys

    //for(int i = 0; i < 5; i++) printf("%x ", roundKeys[i]);

    for(int i = 0; i < 5; i++){
        ciphertext = ciphertext ^ roundKeys[i]; //performing xor with round key

        //since, only in first 4 rounds substitution is performed
        if(i < 4) ciphertext = substitution(ciphertext); //performing substitution

        //since, only in first 3 rounds permutation is performed
        if(i < 3) ciphertext = permutation(ciphertext); //performing permutation
    }

    return ciphertext;
}

//function to decrypt given ciphertext encrypted using the SPN given
uint16_t decryption(uint16_t ciphertext, uint32_t key){
    uint16_t plaintext = ciphertext;
    uint16_t roundKeys[5];
    generateRoundKeys(key, roundKeys); //generating round keys

    //decryption will be done in exact opposite way in which encryption was done

    for(int i = 4; i >= 0; i--){
        //since permuation was done in only first 3 round of encrpytion,
        //therefore inverse permuation will be done only in last 3 rounds of decryption.
        if(i < 3) plaintext = permutation(plaintext); //performing inverse permutation

        //since substitution was done in only first 4 round of encrpytion,
        //therefore inverse substitution will be done only in last 4 rounds of decryption.
        if(i < 4) plaintext = inverseSubstitution(plaintext); //performing inverse substitution

        plaintext = plaintext ^ roundKeys[i]; //performing xor with round keys
    }

    return plaintext;
}

int main(){
    uint16_t plaintext, ciphertext;
    uint32_t key;

    //taking 16 bit plaintext as input in hexadecimal 
    printf("Enter 16-bit plain text in hexadecimal: ");
    scanf("%x", &plaintext);

    //taking 32 bit key as input in hexadecimal 
    printf("Enter 32-bit key in hexadecimal: ");
    scanf("%lx", &key);
    
    //storing the cipher text in the ciphertext variable
    ciphertext = encryption(plaintext, key);
    //printing cipher text
    printf("Ciphertext: %x\n", ciphertext);
    //storing the decrypted text in the decryptedText variable
    uint16_t decryptedText = decryption(ciphertext, key);
    //printing decryptred text
    printf("Decrypted Text: %x", decryptedText);

    return 0;
    
}
