// DES Encryption and Decryption
// By Siddarth Ravishankar

/*
 
 Block size: 64
 Key size  : 64 bit key compressed into 16 sets of 48 bits
 
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <fstream>
#include <streambuf>
#include <sys/time.h>

#define BLOCK_SIZE 64

using namespace std;

enum ProgramType {
    Help,
    KeyGen,
    Encryption,
    Decryption
};

ProgramType programType;

int shiftRounds[16] = {1,1,2,2,2,2,2,2,2,1,2,2,2,2,2,1};
int finalKeys[16][48];

char *inputFile=NULL, *outputFile=NULL;

unsigned long int key;
int keyArray[BLOCK_SIZE];

int initialPermutation[64] = {
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
};

int finalPermutation[64] = {
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25,
};

// Utility functions

//Converts the given 'unsigned long int key' into '64-bit array'

void convertKeyToArray(unsigned long int key, int *_keyArray) {
    
    fill_n(_keyArray, BLOCK_SIZE, 0);
    
    for (int i=0; key>0; i++,key/=2) {
        _keyArray[i]=key%2;
    }
}

//Converts the given 'ascii character block' of size 16 into '64-bit array' (4 bits for each ascii which is equal to 8 ascii hex)

void convertBlockToArray(string block, int *blockArray) {
    
    fill_n(blockArray, BLOCK_SIZE, 0);
    
    for (int i=0; i<block.length(); i++) {
        int val = (int)block[i];
        for (int pos=(block.length()-1-i)*8; val>0; pos++,val/=2) {
            blockArray[pos]=val%2;
        }
    }
}

//Converts the given '64-bit array' into 'ascii character block' of size 16 ascii characters

string convertArrayToBlock(int *blockArray) {
    
    char output[BLOCK_SIZE];
    
    for (int i=0; i<BLOCK_SIZE; i+=8) {
        int val=0;
        for (int j=i; j<i+8; j++) {
            val+=blockArray[j]*pow(2,j-i);
        }
        output[7-i/8] = (char)val;
    }
    output[8]='\0';
    return output;
}

//Returns the hexadecimal value for the binary - 1 hex value per function

char getHexValForBinary(int *hexInBinary) {
    int val=0;
    for (int i=0; i<4; i++) {
        val+=hexInBinary[i]*pow(2,i);
    }
    char hexVal;
    if (val<10) {
        hexVal = '0'+val;
    }
    else {
        hexVal = 'A'+(val-10);
    }
    return hexVal;
}

//Converts the 64-bit block of binary into 16 hex values block (8 Ascii hex)

void convertBinaryToHex(int *binaryBlock, char *hexBlock) {
    
    fill_n(hexBlock, 16, '0');
    for (int i=BLOCK_SIZE-4; i>=0; i-=4) {
        int hexInBinary[4];
        for (int j=i+3; j>=i; j--) {
            hexInBinary[j-i]=binaryBlock[j];
        }
        hexBlock[i/4] = getHexValForBinary(hexInBinary);
    }
}

//Converts the given 16 hex block array into 64-bit binary value

void convertHexBlockToBinary(char *encryptedBlockInHex, int *encryptedBlock) {
    
    fill_n(encryptedBlock, 64, 0);
    for (int i=15; i>=0; i--) {
        int val;
        char hexVal = encryptedBlockInHex[i];
        if (hexVal<='9') {
            val=hexVal-'0';
        }
        else {
            val=hexVal-'A'+10;
        }
        if (val<0 || val>15) {
            cout<<"File corrupt! (Beware, Eve might be evesdropping in the middle)."<<endl;            //Check if file has been modified
            exit(0);
        }
        for (int j=0; val>0; val/=2,j++) {
            encryptedBlock[i*4+j]=val%2;
        }
    }
}

// End of utility functions

//Generate key randomly by using time and CPU cycles as entropy

void generateKey() {
    
    key = 0;
    
    struct timeval timeInterval;
    
    for (int i=0; i<64; i++) {
        gettimeofday(&timeInterval, NULL);
        for (int runs=0; runs<(timeInterval.tv_usec%10)*1000; runs++);      //As different CPUs take different execution time, running on different computers might add more randomness
        gettimeofday(&timeInterval, NULL);
        int entropyValue = (rand()%10)*timeInterval.tv_usec;
        entropyValue = entropyValue/100;
        keyArray[i] = (entropyValue%10)%2;
    }
    
    //Attempt to avoid weak keys
    gettimeofday(&timeInterval, NULL);
    int randomPosition = ((rand()*timeInterval.tv_usec)%58)+5;
    int notWeakerBits[5]={0,1,0,0,1};
    for (int pos=randomPosition,flipBitsPos=0; flipBitsPos<5; flipBitsPos++,randomPosition++) {
        keyArray[randomPosition]=notWeakerBits[flipBitsPos];
    }
    
    if ((rand()*timeInterval.tv_usec)%2==0) {
        for (int i=0; i<64; i++) {
            key = key+((unsigned long int)pow(2,i))*keyArray[i];
        }
    }
    else {
        for (int i=0; i<64; i++) {
            key = key+((unsigned long int)pow(2,i))*keyArray[63-i];
        }
    }
    
    cout<<"0x"<<hex<<key<<endl;
}

//Parse command line arguments

int parseInput(int argv, char **args) {
    
    if (args[1][0]=='-') {
        switch (args[1][1]) {
            case 'h':
                if (argv!=2) {
                    return 0;
                }
                programType = Help;
                return 1;
            case 'k':
                if (argv!=2) {
                    return 0;
                }
                programType = KeyGen;
                return 1;
            case 'e':
            case 'd':
                if (argv!=7) {
                    return 0;
                }
                sscanf(args[2],"%lx",&key);
                for (int i=1; i<argv; i++) {
                    if (args[i][0]=='-') {
                        switch (args[i][1]) {
                            case 'e':
                                programType = Encryption;
                                break;
                            case 'd':
                                programType = Decryption;
                                break;
                            case 'i':
                                inputFile = new char(strlen(args[i+1]));
                                strcpy(inputFile, args[i+1]);
                                break;
                            case 'o':
                                outputFile = new char(strlen(args[i+1]));
                                strcpy(outputFile, args[i+1]);
                                break;
                            default:
                                break;
                        }
                    }
                }
                if (inputFile==NULL || outputFile==NULL) {
                    cout<<"Usage: "<<args[0]<<" -"<<args[1][1]<<" <64_bit_key_in_hex> -i <input_file> -o <output_file>\n";
                    exit(0);
                }
                return 1;
            default:
                return 0;
        }
    }
    else {
        return 0;
    }
}

//Schedule key - creates 16 keys of 48 bits each using the key compression algrithm of DES and stores value in finalKeys

void scheduleKey() {
    
    int pc1Table[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
    int pc2Table[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
    
    int kplus[56];
    
    //PC table 1 permutation
    
    for (int i=0; i<56; i++) {
        kplus[i] = keyArray[pc1Table[i]-1];
    }
    
    //Split and rotate
    
    for (int rounds=0; rounds<16; rounds++) {
        for (int shifts=0; shifts<shiftRounds[rounds]; shifts++) {
            int startVal = kplus[55];
            for (int i=55; i>=29; i--) {
                kplus[i]=kplus[i-1];
            }
            kplus[28]=startVal;
            startVal = kplus[27];
            for (int i=27; i>=1; i--) {
                kplus[i]=kplus[i-1];
            }
            kplus[0]=startVal;
        }
        
        //Compress keys using pc2table
        for (int i=0; i<48; i++) {
            finalKeys[rounds][i]=kplus[pc2Table[i]-1];
        }
    }
    
//    cout<<"Final keys:\n";
//
//    for (int i=0; i<16; i++) {
//        printf("%02d : ",i);
//        for (int j=47; j>=0; j--) {
//            cout<<finalKeys[i][j];
//        }
//        cout<<endl;
//    }
}

//Calculates feistelNetwork function and stores value in output
//Uses expansion permutation, followed by S-box substitution and p-box permutation

void feistelNetwork (int R[], int round, int output[] ) {
    
    int expandedR[48];
    fill_n(expandedR, 48, 0);
    
    //Expansion permutation
    
    int ETable[48] = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
    
    for (int i=0; i<48; i++) {
        expandedR[i] = R[ETable[i]-1];
    }
    
    //Concatnate 48 bits of key with expanded R(i-1)
    
    for (int i=0; i<48; i++) {
        expandedR[i] = expandedR[i]^finalKeys[round][i];
    }
    
    //S-box substitution
    
    int sBoxes[8][4][16] ={
        {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
        {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
        {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
        {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
        {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
        {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
        {{4,11,2,14,15,0,8,13,3,12,9,7,6,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
        {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
    };
    
    int sBoxOutput[32];
    fill_n(sBoxOutput,32,0);
    
    for (int box=7; box>=0; box--) {
        int sBoxNumber = 7-box;
        int sBoxInput[6];
        int startPoint = box*6;
        for (int i=startPoint; i<startPoint+6; i++) {
            sBoxInput[i-startPoint]=expandedR[i];
        }
        int rowNumber = sBoxInput[5]*pow(2,1) + sBoxInput[0]*pow(2,0);
        int columnNumber = sBoxInput[4]*pow(2,3) + sBoxInput[3]*pow(2,2) + sBoxInput[2]*pow(2,1) + sBoxInput[1]*pow(2,0);
        startPoint = box*4;
        
        int sBoxValue = sBoxes[7-box][rowNumber][columnNumber];
        
        for (int pos=startPoint; sBoxValue>0; sBoxValue/=2,pos++) {
            sBoxOutput[pos] = sBoxValue%2;
        }
    }
    
    
    //P-box permutation
    
    int pBoxPermutationTable[32] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
    
    for (int i=0; i<32; i++) {
        output[i] = sBoxOutput[pBoxPermutationTable[i]-1];
    }
    
}

//Algorithm for encryption of each block, runs for 16 times and calls feistelNetwork function - stores encrypted binary values in encryptedBlock

void encryptBlockWithKey(int *blockArray, int *encryptedBlock) {
    
    //Split input data into L and R
    
    int Li[32],Ri[32];
    int c=31;
    for (int i=BLOCK_SIZE-1; i>=32; i--) {
        Li[c--]=blockArray[i];
    }
    c=31;
    for (int i=31; i>=0; i--) {
        Ri[c--]=blockArray[i];
    }
    
    //16 rounds of encryption method
    
    for (int rounds=0; rounds<16; rounds++) {
        int temp[32];
        memcpy(temp, Li, 32*sizeof(int));
        memcpy(Li, Ri, 32*sizeof(int));
        
        int feistelOutput[32];
        fill_n(feistelOutput, 32, 0);
        
        feistelNetwork(Ri, rounds, feistelOutput);
        
        for (int i=0; i<32; i++) {
            temp[i] = temp[i]^feistelOutput[i];     //Temp now has Lrounds
        }
        
        memcpy(Ri, temp, 32*sizeof(int));
        
    }
    
    //Final round of swapping producing cipher text
    
    int temp[32];
    memcpy(temp, Li, 32*sizeof(int));
    memcpy(Li, Ri, 32*sizeof(int));
    memcpy(Ri, temp, 32*sizeof(int));
    
    c=31;
    for (int i=BLOCK_SIZE-1; i>=32; i--) {
        encryptedBlock[i]=Li[c--];
    }
    c=31;
    for (int i=31; i>=0; i--) {
        encryptedBlock[i]=Ri[c--];
    }
    
}

//Algorithm for decryption of each block, runs for 16 times and calls feistelNetwork function - stores decrypted binary values in decryptedBlock

void decryptBlockWithKey(int *blockArray, int *decryptedBlock) {
    
    //Split L and R from input data
    
    int Li[32],Ri[32];
    int c=31;
    for (int i=BLOCK_SIZE-1; i>=32; i--) {
        Li[c--]=blockArray[i];
    }
    c=31;
    for (int i=31; i>=0; i--) {
        Ri[c--]=blockArray[i];
    }
    
    for (int rounds=15; rounds>=0; rounds--) {       //Rounds are reversed with corrosponding keys called by feistel network
        int temp[32];
        memcpy(temp, Li, 32*sizeof(int));
        memcpy(Li, Ri, 32*sizeof(int));
        
        int feistelOutput[32];
        fill_n(feistelOutput, 32, 0);
        
        feistelNetwork(Ri, rounds, feistelOutput);
        
        for (int i=0; i<32; i++) {
            temp[i] = temp[i]^feistelOutput[i];     //Temp now has Lrounds
        }
        
        memcpy(Ri, temp, 32*sizeof(int));
        
    }
    
    //Final round of swapping producing cipher text
    
    int temp[32];
    memcpy(temp, Li, 32*sizeof(int));
    memcpy(Li, Ri, 32*sizeof(int));
    memcpy(Ri, temp, 32*sizeof(int));
    
    c=31;
    for (int i=BLOCK_SIZE-1; i>=32; i--) {
        decryptedBlock[i]=Li[c--];
    }
    c=31;
    for (int i=31; i>=0; i--) {
        decryptedBlock[i]=Ri[c--];
    }
    
}

//Decrypt function reads data from input file, decrypts each block by calling decryptBlockWithKey() and writes it to output file

void decrypt() {
    
    convertKeyToArray(key, keyArray);
    
    scheduleKey();
    
    string output;
    
    ifstream fileIn(inputFile);
    if (!fileIn) {
        cout<<"Error reading input file!"<<endl;
        exit(0);
    }
    
    int encryptedBlock[64];
    int blockArray[64];
    string fileBlock;
    while (fileIn>>fileBlock) {
        
        if (fileBlock.length()<16 || fileBlock.length()>17) {
            cout<<"File corrupt! (Beware, Eve might be evesdropping in the middle)."<<endl;            //Check if file has been modified
            exit(0);
        }
        
        char hexBlock[16];
        
        for (int i=0; i<fileBlock.length(); i++) {
            hexBlock[i]=fileBlock[i];
        }
        
        convertHexBlockToBinary(hexBlock,encryptedBlock);
        
        //Each block is decrypted irrespective of other blocks, ECB mode
        
        decryptBlockWithKey(encryptedBlock, blockArray);
        
        //Final permutation on each block
        int tempBlockArray[BLOCK_SIZE];
        memcpy(tempBlockArray, blockArray, 64*sizeof(int));
        
        for (int i=0; i<64; i++) {
            blockArray[i]=tempBlockArray[finalPermutation[i]-1];
        }
        
        output += convertArrayToBlock(blockArray);
    }
    
    //Discard padded units
    
    int paddedLength = output[output.length()-1]-'0';
    
    ofstream fileOut(outputFile);
    if (!fileOut) {
        cout<<"Error writing to file!\n";
    }
    else {
        
        output = output.substr(0,output.length()-paddedLength);
        
        fileOut<<output;
    }
}

//Encrypt function reads data from input file, encrypts each block by calling encryptBlockWithKey() and writes it to output file (cipher text)

void encrypt() {
    
    ifstream in(inputFile);
    if (!in) {
        cout<<"Error reading input file!"<<endl;
        exit(0);
    }
    string fileContents((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    
    convertKeyToArray(key, keyArray);
    
    scheduleKey();
    
    ofstream fileOut(outputFile);
    
    for (int pos=0; pos<=fileContents.length(); pos+=8) {
        
        string block = fileContents.substr(pos, 8);
        
        //Pad last block with 0s
        
        if (block.length()<8) {
            int paddingLength = 8-block.length();
            for (int i=0; i<paddingLength-1; i++) {
                block += "0";
            }
            char paddingLengthString[2];
            sprintf(paddingLengthString, "%d",paddingLength);
            block += paddingLengthString;
        }
        
        int blockArray[BLOCK_SIZE];
        convertBlockToArray(block, blockArray);
        
        //Initial permutation on each block
        
        int tempBlockArray[BLOCK_SIZE];
        memcpy(tempBlockArray, blockArray, 64*sizeof(int));
        
        for (int i=0; i<64; i++) {
            blockArray[i]=tempBlockArray[initialPermutation[i]-1];
        }
        
        //Each block is encrypted irrespective of other blocks, ECB mode
        
        int encryptedBlock[BLOCK_SIZE];
        encryptBlockWithKey(blockArray, encryptedBlock);
        
        char encryptedBlockInHex[17];
        convertBinaryToHex(encryptedBlock, encryptedBlockInHex);
        
        encryptedBlockInHex[16]='\0';
        
        cout<<encryptedBlockInHex<<endl;
        
        fileOut<<encryptedBlockInHex<<endl;
    }
}


int main(int argv, char **args) {
    
    if (argv<2 || !parseInput(argv, args)) {
        cout<<"Invalid options. Use \""<<args[0]<<" -h\"for list of options.\n";
        return 0;
    }
    
    switch (programType) {
        case Help:
            cout<<"Generate key:\n"<<args[0]<<" -k\n";
            cout<<"Encrypt file:\n"<<args[0]<<" -e <64_bit_key_in_hex> -i <input_file> -o <output_file>\n";
            cout<<"Decrypt file:\n"<<args[0]<<" -d <64_bit_key_in_hex> -i <input_file> -o <output_file>\n\n";
            break;
        case KeyGen:
            generateKey();
            break;
        case Encryption:
            encrypt();
            break;
        case Decryption:
            decrypt();
            break;
        default:
            break;
    }
    
    if (programType==Encryption || programType==Decryption) {
        if (inputFile!=NULL) {
            delete inputFile;
        }
        if (outputFile!=NULL) {
            delete outputFile;
        }
    }
    
    return 0;
}