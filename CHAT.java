// Encrypted chat
// By Siddarth Ravishankar

import java.io.*;
import java.net.*;

public class CHAT {
    
    enum ProgramType {
        ChatServer,
        ChatClient
    };
    
    String keyFile = "";
    String address = "";
    String port = "";
    String sessionKey = "";

    void runServer() throws Exception {         //Alice code
        
        ServerSocket sersock = new ServerSocket(Integer.parseInt(port));
        System.out.println("Alice waits");
        Socket sock = sersock.accept();
        
        PrintWriter pwrite = new PrintWriter(sock.getOutputStream(), true);
        BufferedReader socketReader = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        
        String plainText, cipherText;
        
        //Alice should use alice's private key to decrypt the key encrypted by bob using alice's public key - RSA
        
        RSA rsa = new RSA();
        
        if((cipherText = socketReader.readLine()) != null) {
            cipherText = cipherText.replaceAll("_","\n");
            sessionKey = rsa.decrypt(cipherText,"alice.private");
        }
        
        //Create a new DES session
        
        DES des = new DES(sessionKey);
        
        if(sessionKey.length()>1) {
            plainText = "ok";       //Test encryption key by replying ok message
            cipherText = des.encrypt(plainText);
            pwrite.print(cipherText);
            pwrite.flush();
        }
        
        while(true) {
            if((cipherText = socketReader.readLine()) != null) {        //Once session established, decrypt every message using the DES session created
                cipherText = cipherText.replaceAll("_","\n");           //Avoid the confusion of \n from key stoke and \n from encrypted blocks
                plainText = des.decrypt(cipherText);
                System.out.print("Bob :\t"+plainText+"\nYou :\t");
            }
            plainText = bufferedReader.readLine();
            cipherText = des.encrypt(plainText);                        //Encrypt message to be sent using the DES session created
            cipherText = cipherText.replaceAll("\n","_");
            pwrite.println(cipherText);
            pwrite.flush();
        }
    }
    
    void runClient() throws Exception {                     //Bob code
        
        Socket sock = new Socket(address, Integer.parseInt(port));
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        OutputStream ostream = sock.getOutputStream();
        PrintWriter pwrite = new PrintWriter(ostream, true);   // receiving from server ( socketReader object)
        InputStream istream = sock.getInputStream();
        BufferedReader socketReader = new BufferedReader(new InputStreamReader(istream));
        
        String plainText, cipherText;
        
        //Create a new 64-bit symmetric key
        
        sessionKey = DES.generateKey();
        
        RSA rsa = new RSA();
        cipherText = rsa.encrypt(sessionKey,keyFile);        //Bob should use alice's public key to encrypt the symmetric key
        cipherText = cipherText.replaceAll("\n","_");
        pwrite.println(cipherText);
        pwrite.flush();
        
        DES des = new DES(sessionKey);                              //Establish a DES session if connection is successfull
        
        if((cipherText = socketReader.readLine()) != null) {
            plainText = des.decrypt(cipherText);
            System.out.print("Alice: "+plainText+"\nYou : ");       //Check if the key reached is correct - proceed only if ok is sent by Alice
            if (plainText.equalsIgnoreCase("ok")!=true) {
                System.out.println("Error authenticating.");
                System.exit(0);
            }
        }
        
        while(true) {
            plainText = bufferedReader.readLine();
            cipherText = des.encrypt(plainText);                    //Encrypt message to be sent using the DES session created
            cipherText = cipherText.replaceAll("\n","_");
            pwrite.println(cipherText);
            pwrite.flush();
            if((cipherText = socketReader.readLine()) != null) {
                cipherText = cipherText.replaceAll("_","\n");           //Decrypt message to be sent using the DES session created
                plainText = des.decrypt(cipherText);
                System.out.print("Alice:\t"+plainText+"\nYou :\t");
            }
        }
    }
    
    public static void main(String args[])throws Exception {
        
        ProgramType programType;
        
        if (args[0].equals("-h")) {
            System.out.print("Chat server(Alice): java CHAT -alice -e bob.public -p port -a address\n");
            System.out.print("Chat client( Bob ): java CHAT -bob -e alice.public -p port -a address\n");
            return;
        }
        else if (args[0].equals("-alice")) {
            programType = ProgramType.ChatServer;
        }
        else if (args[0].equals("-bob")) {
            programType = ProgramType.ChatClient;
        }
        else {
            System.out.println("Invalid options. Use java RSA -h\"for list of options.");
            return;
        }
        
        CHAT chat = new CHAT();
        
        for (int i=0; i<args.length; i++) {
            if (args[i].equals("-e")) {
                chat.keyFile = args[i+1];
            }
            else if (args[i].equals("-p")) {
                chat.port = args[i+1];
            }
            else if (args[i].equals("-a")) {
                chat.address = args[i+1];
            }

        }
        
        try {
            switch(programType) {
                case ChatClient:
                    chat.runClient();
                    break;
                    
                case ChatServer:
                    chat.runServer();
                    break;
                    
                default:
                    return;
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        
    }

};