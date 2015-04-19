// RSA Encryption and Decryption
// By Siddarth Ravishankar

import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;
import java.security.SecureRandom;
import java.io.*;

public class RSA {
    
    int keySize = 1024;     //Default keySize or bitSize
    
    enum ProgramType {
        Help,
        KeyGen,
        Encryption,
        Decryption
    };
    
    ProgramType programType;
    
    String inputFile="", outputFile="";
    
    String keyFile;
    
    BigInteger key = BigInteger.valueOf(0);     //Actual key
    
    //Parse the command line arguments and invoke appropriate functions
    
    int parseInput(String args[]) {
        
        if (args[0].charAt(0)=='-') {
            switch (args[0].charAt(1)) {
                case 'h':
                    if (args.length!=1) {
                        return 0;
                    }
                    programType = ProgramType.Help;
                    return 1;
                case 'k':
                    if (args.length==4) {
                        for (int i=0; i<args.length; i++) {
                            if (args[i].equals("-b")) {
                                keySize = Integer.parseInt(args[i+1]);
                                if (keySize<64)
                                    keySize=64;
                            }
                        }
                    }
                    else if (args.length!=2) {
                        return 0;
                    }
                    keyFile = args[1];
                    programType = ProgramType.KeyGen;
                    return 1;
                case 'e':
                case 'd':
                    if (args.length!=6) {
                        return 0;
                    }
                    keyFile = args[1];
                    
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
                                    inputFile = args[i+1];
                                    break;
                                case 'o':
                                    outputFile = args[i+1];
                                    break;
                                default:
                                    break;
                            }
                        }
                    }
                    if (inputFile.length()==0 || outputFile.length()==0) {
                        System.out.println("Usage: RSA -"+args[0].charAt(1)+" <64_bit_key_in_hex> -i <input_file> -o <output_file>");
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
    
    //Encrypts the given plaintext using the key file provided and returns the ciphertext
    
    String encrypt(String plainText, String _keyFile)throws IOException {
        
        BufferedReader fileReader = new BufferedReader(new FileReader(_keyFile));
        
        BigInteger e = new BigInteger(fileReader.readLine(),16);
        String hexN = fileReader.readLine();
        BigInteger n = new BigInteger(hexN,16);
        
        fileReader.close();
        
        String output = "";
        
        keySize = hexN.length() * 4;
        
        int blockSize = (keySize/64) * 5;
        
        //Divide the whole text into blocks based on key size and encrypt each block
        
        for (int pos=0; pos<=plainText.length(); pos+=blockSize) {
            
            String block = "";
            
            if((pos+blockSize)<=plainText.length())
            {
                if (pos!=plainText.length()) {
                    block = plainText.substring(pos, pos+blockSize);
                }
            }
            else {
                
                if (pos!=plainText.length()) {
                    block = plainText.substring(pos, plainText.length());
                }
                
                //Pad last block
                
                int paddingLength = blockSize-block.length();
                for (int i=0; i<paddingLength-1; i++) {
                    block += "0";
                }
                if(paddingLength > 9)
                    paddingLength++;
                if(paddingLength > 99)
                    paddingLength++;
                
                block += String.valueOf(paddingLength);
            }
            
            BigInteger plaintext = new BigInteger(block.getBytes());
            
            //Encryption formula: C = (M^e) mod n
            
            BigInteger ciphertext = plaintext.modPow(e, n);
            output+=ciphertext.toString()+"\n";
            
        }
        
        return output;
    }

    //Decrypts the given ciphertext using the key file provided and returns the plaintext
    
    String decrypt(String cipherText, String _keyFile)throws IOException {
        
        String decryptedText="";
        
        BufferedReader fileReader = new BufferedReader(new FileReader(_keyFile));
        
        BigInteger d = new BigInteger(fileReader.readLine(),16);
        BigInteger n = new BigInteger(fileReader.readLine(),16);
        
        fileReader.close();
        
        String[] encryptedBlocks = cipherText.split("\n");
        
        for(String encryptedBlock : encryptedBlocks) {
            
            BigInteger ciphertext = new BigInteger(encryptedBlock);
            
            //Decryption formula: M = (C^d) mod n
            
            BigInteger plaintext = ciphertext.modPow(d, n);
            
            decryptedText += new String(plaintext.toByteArray());
          
        }
        fileReader.close();
        
        int paddedLength = 0;
        
        int pos;
        
        for(pos=decryptedText.length()-1; decryptedText.charAt(pos-1)!='0'; pos--);
        
        for(; pos<decryptedText.length(); pos++) {
            paddedLength = paddedLength*10 + ((int)decryptedText.charAt(pos)-'0');
        }
        
        decryptedText = decryptedText.substring(0,decryptedText.length()-paddedLength);
        return decryptedText;
        
    }
    
    //Generate random public and private key pair
    
    void generateKey ()throws Exception {
        
        long time;
        SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
        
        for (int runs=0; runs<(rand.nextInt()%10)*1000; runs++);      //As different CPUs take different execution time, running on different computers might add more randomness
        time = System.nanoTime()/1000;
        int entropyValue = (rand.nextInt()%10)*(int)time;
        if (entropyValue<0) {
            entropyValue*=-1;
        }
        
        
        rand.setSeed(entropyValue);
        
        BigInteger p, q;
        p = BigInteger.probablePrime(keySize/2, rand);
        q = BigInteger.probablePrime(keySize/2, rand);
        
        BigInteger n = p.multiply(q);
        
        //Public key = (e,n)
        
        BigInteger phi_n = (p.subtract(BigInteger.valueOf(1))).multiply(q.subtract(BigInteger.valueOf(1)));
        
        BigInteger e = BigInteger.valueOf(17);
        
        e = new BigInteger("3");
        while (phi_n.gcd(e).intValue() != 1) {
            e = e.add(BigInteger.valueOf(2));       //Definitely even numbers are not prime
        }
        
        String hexE = new BigInteger(e.toString()).toString(16);
        
        String hexKey = new BigInteger(n.toString()).toString(16);
        
        PrintWriter writer = new PrintWriter(keyFile+".public", "UTF-8");
        writer.print(hexE+"\n"+hexKey);
        writer.close();
        
        //Private key = (d=e_inv mod pi(n),n)
        
        BigInteger d = e.modInverse(phi_n);
        
        String hexD = new BigInteger(d.toString()).toString(16);
        
        writer = new PrintWriter(keyFile+".private", "UTF-8");
        writer.print(hexD+"\n"+hexKey);
        writer.close();
        
    }
    
    public static String getFileContents(String fileName)throws Exception {
        
        BufferedReader fileReader = new BufferedReader(new FileReader(fileName));
        String fileContents = "";
        String line;
        while ((line = fileReader.readLine()) != null) {
            fileContents += line+"\n";
        }
        fileReader.close();
        
        int fileLength = (int)(new File(fileName)).length();
        
        if(fileContents.length()==fileLength+1) {
            fileContents = fileContents.substring(0,fileContents.length()-1);
        }
        return fileContents;
    }
    
    
    public static void main(String args[])throws Exception {
        
        RSA rsa = new RSA();
        
        if (args.length<1 || (rsa.parseInput(args)!=1) ) {
            System.out.println("Invalid options. Use java RSA -h\"for list of options.");
            return;
        }
        
        try {
            switch (rsa.programType) {
                case Help:
                    System.out.print("Generate key: java RSA -k <key_file> -b <bit_size>\n");
                    System.out.print("Encrypt file: java RSA -e <key file>.public -i <input file> -o <output file>\n");
                    System.out.print("java RSA -d <key file>.private -i <input file> -o <output file>\n");
                    break;
                case KeyGen:
                    rsa.generateKey();
                    break;
                case Encryption:
                    
                    String encryptedBlocks = rsa.encrypt(getFileContents(rsa.inputFile), rsa.keyFile);
                    PrintWriter writer = new PrintWriter(rsa.outputFile, "UTF-8");
                    writer.print(encryptedBlocks);
                    writer.close();
                    
                    break;
                case Decryption:
                    
                    String decryptedText = rsa.decrypt(getFileContents(rsa.inputFile), rsa.keyFile);
                    writer = new PrintWriter(rsa.outputFile, "UTF-8");
                    writer.print(decryptedText);
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