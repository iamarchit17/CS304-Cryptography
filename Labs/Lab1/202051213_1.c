#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#define MAX 100

/*
Archit Agrawal
202051213
*/

//this function takes the input plaintext anf generate a playfairString according to the rules of Playfair cipher.
int makePlayfairString(char* plaintext, char* playfairString){
    int index = 0;

    for(int i = 0; i < strlen(plaintext); i += 2){
        char c1 = plaintext[i];
        //if we get c1 only and plaintext is over, we make c2 = 'x'
        char c2 = ((i+1) < strlen(plaintext)) ? plaintext[i+1] : 'x';

        if(c1 == 'j') c1 = 'i'; //checking if c1 = 'j', if it is, changing it to 'i'
        if(c2 == 'j') c2 = 'i'; //checking if c2 = 'j', if it is, changing it to 'i'

        //if there is repetition that is, if c1 == c2, we make c2 = x
        //also we need to consider the character plaintext[i+1] now, hence, decremented 'i'
        if(c2 == c1){
            c2 = 'x';
            i--;
        }

        playfairString[index++] = c1;
        playfairString[index++] = c2;
    }

    return index;
    
}

//this function builds the matrix of Playfair Cipher using the key
char* buildMatrixFromKey(char* key){
    int isPresent[26] = {0}; //stores which characters have appeared in the matrix 
    //if isPresent[i] == 1, it means (char) (i + 97) is already present in matrix
    
    //convertint the 'j' in key to 'i'
    for(int i = 0; i < strlen(key); i++){
        if(key[i] == 'j') key[i] = 'i';
    }

    isPresent[9] = 1; //since 'j' is not considered in building the matrix
    
    int r = 0;
    char* matrix = (char*) malloc(MAX * 1);
    
    //adding the characters from the key in the matrix
    for(int i = 0; i < strlen(key); i++){
        if(isPresent[key[i] - 97] == 0){ //if char is not present
            matrix[r++] = key[i];        //addint it in matrix
            isPresent[key[i] - 97] = 1;  //and setting it as present in matrix
        }
    }

    //adding remaining alphabets that were not present in the key, to the matrix
    for(int i = 0; i < 26; i++){
        if(isPresent[i] == 0){  //if it is absent in matrix
            isPresent[i] = 1;   //mark it present
            matrix[r++] = (char) (i + 97);  //add it in matrix
        }
    }

    return matrix;
}

//function to find the first appeareance index of a character in a string
int findCharPos(char* matrix, char x){
    for(int i = 0; i < strlen(matrix); i++){
        if(matrix[i] == x) return i;
    }

    return -1;
}

//function to find gcd using extended euclidean algorithm
//here, gcd is not required, we are more interested in finding multiplicative inverse
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

//function to perform playfair encrpytion
char* encryptPlayfair(char* matrix, char* playfairString, int length){
    char* encrypted = (char*) malloc(MAX * 1); //stores encrypted text

    for(int i = 0; i < length; i += 2){

        char c1 = playfairString[i];
        char c2 = playfairString[i+1]; 

        int pos1 = findCharPos(matrix, c1); //finding position of c1 in string 'matrix'
        int pos2 = findCharPos(matrix, c2); //finding position of c2 in string 'matrix'

        //if index = i for character x
        //then its row in the matrix will be i/5 and column will be i%5

        int row1 = pos1/5; 
        int col1 = pos1%5;
        int row2 = pos2/5;
        int col2 = pos2%5;
        /*
        if char x is in row 'r' and column 'c' in the matrix,
        then its location in string is (5 * r + c)
        */

        //if both c1 and c2 are in same row
        if(row1 == row2) {
            col1 = (col1 + 1) % 5; //moving to the next right column of c1 in the matrix
            encrypted[i] = matrix[row1 * 5 + col1]; 

            col2 = (col2 + 1) % 5; //moving to the next right column of c2 in the matrix
            encrypted[i+1] = matrix[row1 * 5 + col2];

        } else if(col1 == col2){ //if c1 and c2 are in same column
            row1 = (row1 + 1) % 5; //moving to next bottom row of c1 in the matrix
            encrypted[i] = matrix[row1 * 5 + col1];

            row2 = (row2 + 1) % 5; //moving to next bottom row of c2 in the matrix
            encrypted[i+1] = matrix[row2 * 5 + col1];

        } else { //if c1 and c2 are in different rows and different columns
            //swapping the columns for c1 and c2
            int temp = col1;
            col1 = col2;
            col2 = temp;

            encrypted[i] = matrix[row1 * 5 + col1]; 
            encrypted[i+1] = matrix[row2 * 5 + col2];
        }
    }

    return encrypted;
}

//function to perform playfair decrpytion
char* decryptPlayfair(char* matrix, char* encrypted, int length){
    char* decrypted = (char*) malloc (MAX * 1); //stores decrypted text

    for(int i = 0; i < length; i += 2){

        char c1 = encrypted[i];
        char c2 = encrypted[i+1];

        int pos1 = findCharPos(matrix, c1); //finding position of c1 in string 'matrix'
        int pos2 = findCharPos(matrix, c2); //finding position of c2 in string 'matrix'

        //if index = i for character x
        //then its row in the matrix will be i/5 and column will be i%5

        int row1 = pos1/5;
        int col1 = pos1%5;
        int row2 = pos2/5;
        int col2 = pos2%5;

        /*
        if char x is in row 'r' and column 'c' in the matrix,
        then its location in string is (5 * r + c)
        */

        //if both c1 and c2 are in same row
        if(row1 == row2) {
            col1 = (col1 + 5 - 1) % 5; //moving to the next left column of c1 in the matrix
            decrypted[i] = matrix[row1 * 5 + col1];

            col2 = (col2 + 5 - 1) % 5; //moving to the next left column of c2 in the matrix
            decrypted[i+1] = matrix[row1 * 5 + col2];

        } else if(col1 == col2){
            row1 = (row1 + 5 - 1) % 5; //moving to next upper row of c1 in the matrix
            decrypted[i] = matrix[row1 * 5 + col1];

            row2 = (row2 + 5 - 1) % 5; //moving to next upper row of c2 in the matrix
            decrypted[i+1] = matrix[row2 * 5 + col1];

        } else { //if c1 and c2 are in different rows and different columns
            //swapping the columns for c1 and c2
            int temp = col1;
            col1 = col2;
            col2 = temp;

            decrypted[i] = matrix[row1 * 5 + col1];
            decrypted[i+1] = matrix[row2 * 5 + col2];
        }
    }

    return decrypted;
}

//function to perform affine encryption
char* encryptAffine(char* plaintext, int length, int a, int b){
    char* cipher;
    cipher = (char*)malloc(MAX * 1);

    for(int i = 0; i < length; i++) cipher[i] = ((a * (plaintext[i] - 'a') + b) % 26) + 'a';
    return cipher;
}

//function to perform affine decryption
char* decryptAffine(char* ciphertext, int length, int a, int b){

    int p, q;
    int gcd = extendedEuclidean(a, 26, &p, &q); //for finding multiplicative inverse of a under modulo 26
    //gcd != mulitplicative inverse, instead p is multiplicative inverse
    while(p < 0) p += 26; //p can be negative, but we need positive value

    char* plain;
    plain = (char*)malloc(MAX * 1);

    for(int i = 0; i < length; i++) plain[i] = ((p * ( (ciphertext[i] - 'a') + 26 - b)) % 26) + 'a';
    return plain;
}

//function to perform shift encrpytion
char* encryptShift(char* plaintext, int length, int key){
    char* cipher;
    cipher = (char*)malloc(MAX * 1);

    for(int i = 0; i < length; i++) cipher[i] = (((plaintext[i] - 'a') + key) % 26) + 'a';
    return cipher;
}

//function to perform shift decrpytion
char* decryptShift(char* ciphertext, int length, int key){
    char* plain;
    plain = (char*)malloc(MAX * 1);

    for(int i = 0; i < length; i++) plain[i] = (((ciphertext[i] - 'a') + 26 - key) % 26) + 'a';
    return plain;
}

//function to print a string
void printString(char* string, int length){
    for(int i = 0; i < length; i++){
        printf("%c", string[i]);
    }

    printf("\n");
}

//function to print a matrix
void printMatrix(char* matrix){
    printf("Matrix Generated From Given Key:\n");
    for(int i = 0; i < 5; i++){
        for(int j = 0; j < 5; j++){
            printf("%c ", matrix[i * 5 + j]);
        }

        printf("\n");
    }

    printf("\n");
}

int main(){
    char* plaintext = (char*) malloc(MAX * 1);

    printf("Enter Plaintext: ");
    gets(plaintext); //taking plaintext as input

    char* playfairString = (char*) malloc(MAX * 1);

    int lengthPlayfairString = makePlayfairString(plaintext, playfairString); //creating 'delta' or the playfair String
    printf("Playfair String: ");
    printString(playfairString, lengthPlayfairString); //printing 'delta'

    char* keyPlayfair = (char*) malloc(MAX * 1);
    printf("Enter key for Playfair Cipher: ");
    gets(keyPlayfair); //taking key for playfair cipher as input
 
    char* matrix = (char*) malloc(MAX * 1);
    matrix = buildMatrixFromKey(keyPlayfair); //building playfair matrix from it
    printMatrix(matrix); //printing the playfair matrix


    char* encryptedPlayfair = encryptPlayfair(matrix, playfairString, lengthPlayfairString); //performing playfair encryption
    printf("Cipher Text C1 (using Playfair Cipher): ");
    printString(encryptedPlayfair, lengthPlayfairString); //printing playfair encrypted text C1


    char* encryptedAffine = encryptAffine(encryptedPlayfair, lengthPlayfairString, 11, 15); //performing affine encryption
    printf("Cipher Text C2 (using Affine Cipher): ");
    printString(encryptedAffine, lengthPlayfairString); //printing affine encrypted text C2

    int keyShift; 
    printf("Enter Key for Shift Cipher: "); 
    scanf("%d", &keyShift); //taking key for shift cipher as input

    keyShift %= 26; //if a large key is entered, shift will still be in 0 to 25.

    char* encryptedShift = encryptShift(encryptedAffine, lengthPlayfairString, keyShift); //performing shift encryption
    printf("Cipher Text C3 (using Shift Cipher): ");
    printString(encryptedShift, lengthPlayfairString); //printing shift encrypted text C3
    
    printf("\n\n");

    char* decryptedShift = decryptShift(encryptedShift, lengthPlayfairString, keyShift); //decrypting shift encryption
    printf("Decrypted Text P3 (using Shift Decryption): ");
    printString(decryptedShift, lengthPlayfairString); //printing shift decryption P3

    char* decryptedAffine = decryptAffine(decryptedShift, lengthPlayfairString, 11, 15); //decrypting affine encryption
    printf("Decrypted Text P2 (using Affine Decryption): ");
    printString(decryptedAffine, lengthPlayfairString); //printing affine decryption P2

    char* decryptedPlayfair = decryptPlayfair(matrix, decryptedAffine, lengthPlayfairString); //decrypting playfair encryption
    printf("Decrypted Text P1 (using Playfair Decryption): "); 
    printString(decryptedPlayfair, lengthPlayfairString); //printing playfair decryption P1

    return 0;
}