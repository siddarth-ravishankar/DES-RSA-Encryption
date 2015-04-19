// DES Encryption and Decryption
// By Siddarth Ravishankar

/*
 
 Block size: 64
 Key size  : 64 bit key compressed into 16 sets of 48 bits
 
 */

import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;
import java.io.*;

class DES {
    
    int BLOCK_SIZE = 64;
    
    enum ProgramType {
        Help,
        KeyGen,
        Encryption,
        Decryption
    };
    
    ProgramType programType;
    
    String inputFile="", outputFile="";
    
    int[][] finalKeys = new int [16][48];
    
    String keyString = "";
    
    int[] initialPermutation = {
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
    };
    
    int[] finalPermutation = {
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25,
    };
    
    //Utility functions
    
    //Converts the given 'key' into '64-bit binary key array'
    
    void convertKeyToBinaryArray(BigInteger _key, int[] _keyArray) {
        
        for (int i=0; _key.signum()==1; i++) {
            _keyArray[i]=(_key.mod(BigInteger.valueOf(2))).intValue();;
            _key = _key.divide(BigInteger.valueOf(2));
        }
    }
    
    //Converts the given 'ascii character block' of size 16 into '64-bit array' (4 bits for each ascii which is equal to 8 ascii hex)
    
    void convertTextBlockToBinaryArray(String block, int[] blockArray) {
        
        for (int i=0; i<block.length(); i++) {
            int val = (int)block.charAt(i);
            for (int pos=(block.length()-1-i)*8; val>0; pos++,val/=2) {
                blockArray[pos]=val%2;
            }
        }
    }
    
    //Converts the given '64-bit array' into 'ascii character block' of size 16 ascii characters and returns the text block
    
    String convertBinaryArrayToTextBlock(int[] blockArray) {
        
        String output = "";
        
        for (int i=0; i<BLOCK_SIZE; i+=8) {
            int val=0;
            for (int j=i; j<i+8; j++) {
                val+=blockArray[j]*(int)Math.pow(2,j-i);
            }
            output += (char)val;
        }
        
        output = new StringBuilder(output).reverse().toString();
        
        return output;
    }
    
    //Returns the hexadecimal value for the binary - 1 hex value per function
    
    char getHexValForBinary(int[] hexInBinary) {
        int val=0;
        for (int i=0; i<4; i++) {
            val+=hexInBinary[i]*(int)Math.pow(2,i);
        }
        char hexVal;
        if (val<10) {
            hexVal = (char)((int)'0'+val);
        }
        else {
            hexVal = (char)((int)'A'+val-10);
        }
        return hexVal;
    }
    
    //Converts the 64-bit block of binary into 16 hex values block (8 Ascii hex)
    
    String convertBinaryToHex(int[] binaryBlock) {
        
        String hexBlock = "";
        
        for (int i=60; i>=0; i-=4) {
            int[] hexInBinary = new int[4];
            for (int j=i+3; j>=i; j--) {
                hexInBinary[j-i]=binaryBlock[j];
            }
            hexBlock += getHexValForBinary(hexInBinary);
        }
        
        hexBlock = new StringBuilder(hexBlock).reverse().toString();
        return hexBlock;
    }
    
    //Converts the given 16 hex block array into 64-bit binary value
    
    void convertHexBlockToBinary(String encryptedBlockInHex, int[] encryptedBlock) {
        
        for (int i=15; i>=0; i--) {
            int val;
            char hexVal = encryptedBlockInHex.charAt(i);
            if (hexVal<='9') {
                val=hexVal-(int)'0';
            }
            else {
                val=hexVal-(int)'A'+10;
            }
            if (val<0 || val>15) {
                System.out.println("File corrupt! (Beware, Eve might be evesdropping in the middle).");            //Check if file has been modified
                System.exit(0);
            }
            for (int j=0; val>0; val/=2,j++) {
                encryptedBlock[i*4+j]=val%2;
            }
        }
    }
    
    
    //End of utility functions
    
    public DES(String _keyString) {
        keyString = _keyString;
    }
    
    public int parseInput(String args[]) {
        
        if (args[0].charAt(0)=='-') {
            switch (args[0].charAt(1)) {
                case 'h':
                    if (args.length!=1) {
                        return 0;
                    }
                    programType = ProgramType.Help;
                    return 1;
                case 'k':
                    if (args.length!=1) {
                        return 0;
                    }
                    programType = ProgramType.KeyGen;
                    return 1;
                case 'e':
                case 'd':
                    if (args.length!=6) {
                        return 0;
                    }
                    keyString = args[1];
                    
                    for (int i=0; i<args.length; i++) {
                        if (args[i].charAt(0)=='-') {
                            switch (args[i].charAt(1)) {
                                case 'e':
                                    programType = ProgramType.Encryption;
                                    break;
                                case 'd':
                                    programType = ProgramType.Decryption;
                                    break;
                                case 'i':
                                    inputFile = new String();
                                    inputFile = args[i+1];
                                    break;
                                case 'o':
                                    outputFile = new String();
                                    outputFile = args[i+1];
                                    break;
                                default:
                                    break;
                            }
                        }
                    }
                    if (inputFile.length()==0 || outputFile.length()==0) {
                        System.out.println("Usage: DES -"+args[0].charAt(1)+" <64_bit_key_in_hex> -i <input_file> -o <output_file>");
                        System.exit(0);
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
    
    void scheduleKey(BigInteger key) {
        
        int[] keyArray = new int[64];
        
        convertKeyToBinaryArray(key, keyArray);
        
        int[] pc1Table = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
        int[] pc2Table = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
        
        int[] shiftRounds = {1,1,2,2,2,2,2,2,2,1,2,2,2,2,2,1};
        
        int[] kplus = new int[56];
        
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
    }
    
    //Calculates feistelNetwork function and stores value in output
    //Uses expansion permutation, followed by S-box substitution and p-box permutation
    
    void feistelNetwork (int[] R, int round, int[] output ) {
        
        int[] expandedR = new int[48];
        
        //Expansion permutation
        
        int[] ETable = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
        
        for (int i=0; i<48; i++) {
            expandedR[i] = R[ETable[i]-1];
        }
        
        //Concatnate 48 bits of key with expanded R(i-1)
        
        for (int i=0; i<48; i++) {
            expandedR[i] = expandedR[i]^finalKeys[round][i];
        }
        
        //S-box substitution
        
        int[][][] sBoxes ={
            {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
            {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
            {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
            {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
            {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
            {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
            {{4,11,2,14,15,0,8,13,3,12,9,7,6,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
            {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
        };
        
        int[] sBoxOutput = new int[32];
        
        for (int box=7; box>=0; box--) {
            int sBoxNumber = 7-box;
            int[] sBoxInput = new int[6];
            int startPoint = box*6;
            for (int i=startPoint; i<startPoint+6; i++) {
                sBoxInput[i-startPoint]=expandedR[i];
            }
            
            //Split rows and columns
            
            int rowNumber = sBoxInput[5]*(int)Math.pow(2,1) + sBoxInput[0]*(int)Math.pow(2,0);
            int columnNumber = sBoxInput[4]*(int)Math.pow(2,3) + sBoxInput[3]*(int)Math.pow(2,2) + sBoxInput[2]*(int)Math.pow(2,1) + sBoxInput[1]*(int)Math.pow(2,0);
            startPoint = box*4;
            
            int sBoxValue = sBoxes[7-box][rowNumber][columnNumber];
            
            for (int pos=startPoint; sBoxValue>0; sBoxValue/=2,pos++) {     //S-box substituted in binary
                sBoxOutput[pos] = sBoxValue%2;
            }
        }
        
        //P-box permutation
        
        int[] pBoxPermutationTable = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
        
        for (int i=0; i<32; i++) {
            output[i] = sBoxOutput[pBoxPermutationTable[i]-1];
        }
        
    }
    
    //Algorithm for encryption of each block, runs for 16 times and calls feistelNetwork function - stores encrypted binary values in encryptedBlock
    
    void encryptBlockWithKey(int[] blockArray, int[] encryptedBlock) {
        
        //Split input data into L and R
        
        int[] Li = new int[32];
        int[] Ri = new int[32];
        int c=31;
        for (int i=63; i>=32; i--) {
            Li[c--]=blockArray[i];
        }
        c=31;
        for (int i=31; i>=0; i--) {
            Ri[c--]=blockArray[i];
        }
        
        //16 rounds of encryption method
        
        for (int rounds=0; rounds<16; rounds++) {
            int[] temp = new int[32];
            System.arraycopy( Li, 0, temp, 0, 32);
            System.arraycopy( Ri, 0, Li, 0, 32);
            
            int[] feistelOutput = new int[32];
            
            feistelNetwork(Ri, rounds, feistelOutput);
            
            for (int i=0; i<32; i++) {
                temp[i] = temp[i]^feistelOutput[i];     //Temp now has Lrounds
            }
            
            System.arraycopy( temp, 0, Ri, 0, 32);
        }
        
        //Final round of swapping producing cipher text
        
        int[] temp = new int[32];
        System.arraycopy( Li, 0, temp, 0, 32);
        System.arraycopy( Ri, 0, Li, 0, 32);
        System.arraycopy( temp, 0, Ri, 0, 32);
        
        c=31;
        for (int i=BLOCK_SIZE-1; i>=32; i--) {
            encryptedBlock[i]=Li[c--];
        }
        c=31;
        for (int i=31; i>=0; i--) {
            encryptedBlock[i]=Ri[c--];
        }
        
    }
    
    //Encrypt function reads data from input file, encrypts each block by calling encryptBlockWithKey() and writes it to output file (cipher text)
    
    public String encrypt(String plainText)throws IOException {
        
        BigInteger key = new BigInteger(keyString, 16);
        
        scheduleKey(key);
        
        String output = "";
        
        for (int pos=0; pos<=plainText.length(); pos+=8) {
            
            String block = "";
            
            if((pos+8)<=plainText.length())
            {
                if (pos!=plainText.length()) {
                    block = plainText.substring(pos, pos+8);
                }
            }
            else {
                
                if (pos!=plainText.length()) {
                    block = plainText.substring(pos, plainText.length());
                }
                
                
                int paddingLength = 8-block.length();
                for (int i=0; i<paddingLength-1; i++) {
                    block += "0";
                }
                block += String.valueOf(paddingLength);
            }
            
            int[] blockArray = new int[64];
            convertTextBlockToBinaryArray(block, blockArray);
            
            //Initial permutation on each block
            
            int[] tempBlockArray = new int[64];
            System.arraycopy( blockArray, 0, tempBlockArray, 0, 64);
            
            for (int i=0; i<64; i++) {
                blockArray[i]=tempBlockArray[initialPermutation[i]-1];
            }
            
            //Each block is encrypted irrespective of other blocks, ECB mode
            
            int[] encryptedBlock = new int[64];
            encryptBlockWithKey(blockArray, encryptedBlock);
            
            String encryptedBlockInHex = "";
            encryptedBlockInHex = convertBinaryToHex(encryptedBlock);
            
            output+=encryptedBlockInHex+"\n";
            
        }
        return output;
        
    }
    
    //Algorithm for decryption of each block, runs for 16 times and calls feistelNetwork function - stores decrypted binary values in decryptedBlock
    
    void decryptBlockWithKey(int[] blockArray, int[] decryptedBlock) {
        
        //Split input data into L and R
        
        int[] Li = new int[32];
        int[] Ri = new int[32];
        int c=31;
        for (int i=63; i>=32; i--) {
            Li[c--]=blockArray[i];
        }
        c=31;
        for (int i=31; i>=0; i--) {
            Ri[c--]=blockArray[i];
        }
        
        //16 rounds of decryption method
        
        for (int rounds=15; rounds>=0; rounds--) {
            int[] temp = new int[32];
            System.arraycopy( Li, 0, temp, 0, 32);
            System.arraycopy( Ri, 0, Li, 0, 32);
            
            int[] feistelOutput = new int[32];
            
            feistelNetwork(Ri, rounds, feistelOutput);
            
            for (int i=0; i<32; i++) {
                temp[i] = temp[i]^feistelOutput[i];     //Temp now has Lrounds
            }
            
            System.arraycopy( temp, 0, Ri, 0, 32);
        }
        
        //Final round of swapping producing cipher text
        
        int[] temp = new int[32];
        System.arraycopy( Li, 0, temp, 0, 32);
        System.arraycopy( Ri, 0, Li, 0, 32);
        System.arraycopy( temp, 0, Ri, 0, 32);
        
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
    
    public String decrypt(String cipherText)throws IOException {
        
        BigInteger key = new BigInteger(keyString, 16);
        
        scheduleKey(key);
        
        String plainText = "";
        
        String[] encryptedHexBlocks = cipherText.split("\n");
        
        for (int blockNo=0; blockNo<encryptedHexBlocks.length; blockNo++) {
            
            int[] encryptedBlock = new int[64];
            
            convertHexBlockToBinary(encryptedHexBlocks[blockNo],encryptedBlock);
            
            //Each block is decrypted irrespective of other blocks, ECB mode
            
            decryptBlockWithKey(encryptedBlock, encryptedBlock);
            
            //Final permutation on each block
            int[] tempBlockArray = new int[64];
            System.arraycopy( encryptedBlock, 0, tempBlockArray, 0, 64);
            
            for (int i=0; i<64; i++) {
                encryptedBlock[i]=tempBlockArray[finalPermutation[i]-1];
            }
            
            String output = convertBinaryArrayToTextBlock(encryptedBlock);
            
            if( blockNo == encryptedHexBlocks.length-1 ) {
                int paddedLength = (int)(output.charAt(7) - '0');
                output = output.substring(0, 8-paddedLength);
            }
            
            plainText+=output;
        }
        
        return plainText;
    }
    
    public static String generateKey () {
        
        long time;
        Random rand = new Random();
        
        int[] keyArray = new int[64];
        
        for (int i=0; i<64; i++) {
            for (int runs=0; runs<(rand.nextInt()%10)*1000; runs++);      //As different CPUs take different execution time, running on different computers might add more randomness
            time = System.nanoTime()/1000;
            int entropyValue = (rand.nextInt()%10)*(int)time;
            if (entropyValue<0) {
                entropyValue*=-1;
            }
            entropyValue = entropyValue/100;
            keyArray[i] = (entropyValue%10)%2;
        }
        
        //Attempt to avoid weak keys
        time = (System.nanoTime()/1000)%1000;
        int randomPosition = (int)((rand.nextInt(1)*time)%58)+5;
        int[] notWeakerBits={0,1,0,0,1};
        for (int pos=randomPosition,flipBitsPos=0; flipBitsPos<5; flipBitsPos++,randomPosition++) {     //Avoids the consecutive 0P, 0F and PF
            keyArray[randomPosition]=notWeakerBits[flipBitsPos];
        }
        BigInteger key = BigInteger.valueOf(0);
        for (int i=0; i<64; i++) {
            BigInteger val = BigInteger.valueOf(2).pow(i);
            key = key.add(val.multiply(BigInteger.valueOf(keyArray[i])));
        }
        
        String hexKey = new BigInteger(key.toString()).toString(16);
        return hexKey;
    }
    
    public static void main(String args[])throws IOException {
        
        DES des = new DES("");
        
        if (args.length<1 || (des.parseInput(args)!=1) ) {
            System.out.println("Invalid options. Use java DES -h\"for list of options.");
            return;
        }
        
        try {
            switch (des.programType) {
                case Help:
                    System.out.print("Generate key: java DES -k\n");
                    System.out.print("Encrypt file: java DES -e <64_bit_key_in_hex> -i <input_file> -o <output_file>\n");
                    System.out.print("Decrypt file: java DES -d <64_bit_key_in_hex> -i <input_file> -o <output_file>\n");
                    break;
                case KeyGen:
                    System.out.println(DES.generateKey());
                    break;
                case Encryption:
                    
                    BufferedReader fileReader = new BufferedReader(new FileReader(des.inputFile));
                    String fileContents = "";
                    String line;
                    while ((line = fileReader.readLine()) != null) {
                        fileContents += line+"\n";
                    }
                    fileReader.close();
                    
                    int fileLength = (int)(new File(des.inputFile)).length();
                    
                    if(fileContents.length()==fileLength+1) {
                        fileContents = fileContents.substring(0,fileContents.length()-1);
                    }
                    
                    PrintWriter writer = new PrintWriter(des.outputFile, "UTF-8");
                    writer.print(des.encrypt(fileContents));
                    writer.close();
                    break;
                case Decryption:
                    
                    fileContents = new Scanner(new File(des.inputFile)).useDelimiter("\\Z").next();
                    writer = new PrintWriter(des.outputFile, "UTF-8");
                    writer.print(des.decrypt(fileContents));
                    writer.close();
                    break;
                    
                default:
                    break;
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }
};