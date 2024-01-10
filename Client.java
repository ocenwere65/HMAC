package hmac;

import static hmac.Server.SERVER_PORT;
import static hmac.Server.decryption;
import static hmac.Server.verify;
import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import javax.xml.bind.DatatypeConverter;

public class Client {
    
    //Two variables needed for socket programming
    public static final String SERVER_IP = "localhost";
    public static final int SERVER_PORT = 9001;
    
    private static Cipher encrypt; //encryption cipher
    private static Cipher decrypt; //decryption cipher
    
    private static SecretKey DES_KEY; //secret key for DES
    private static Mac HMAC_SHA_KEY; //secret key for HMAC
    
    //Strings used for HMAC
    private static final String key = "imthekey";
    private static final String secret = "secret";
    
    public static void main(String args[]) throws IOException{
        Scanner console = new Scanner(System.in); //declare Scnner variable
        String writeDESKey = "", writeHMACKey = ""; //strings to write the keys into a shared file
        PrintStream DES_KEY_File, HMAC_KEY_File; //to print key to text files
        PrintStream index; //To create file to hold the length of message string
        Scanner get_Index; //To scan the index from shared file to split concatenation
        
        try{
            //Generate DES Key
            DES_KEY = KeyGenerator.getInstance("DES").generateKey(); //call Key generator method to construct key
            writeDESKey = Base64.getEncoder().encodeToString(DES_KEY.getEncoded()); //convert secret kay variable to string
            DES_KEY_File = new PrintStream(new File("DESKey.txt")); //generate new text file to store DES key
            DES_KEY_File.println(writeDESKey); //print string to file
            
            //Generate HMAC Key
            HMAC_SHA_KEY = Mac.getInstance("HmacSHA256"); //get instance of Mac variable
            HMAC_SHA_KEY.init(new SecretKeySpec(key.getBytes(), "HmacSHA256")); //initialize Mac variable
            writeHMACKey = key; //convert secret key variable to string
            HMAC_KEY_File = new PrintStream(new File("HMACKey.txt")); //generate new text file to store HMAC key
            HMAC_KEY_File.println(key); //print string to file
        }catch(Exception e){
            System.out.println();
        }

        ServerSocket listener = new ServerSocket(SERVER_PORT); //set up server socket
        
        System.out.println("[CLIENT] Waiting for server connection ...");
        Socket client = listener.accept(); //client is connected with server
        System.out.println("[CLIENT] Accept new connection from 127.0.0.1");
        PrintWriter output = new PrintWriter(client.getOutputStream(), true);
        
        try{
            while(true){
                System.out.println();
                String m1 = console.nextLine(); //get user input
                
                if(m1.equalsIgnoreCase("Goodbye.")) break; //If client says 'Goodbye' break out of loop
                
                //Place length of message into newly declared index file
                index = new PrintStream(new File("Index.txt"));
                index.println(m1.length());
        
                //display shared keys and user input
                System.out.println();
                System.out.println("Shared DES Key is: " + writeDESKey);
                System.out.println("Shared HMAC Key is: " + writeHMACKey);
                System.out.println("Plain message is: " + m1);
        
                encryption(m1, output); //call encryption method
        
                //Read from Server's encrypted message
                BufferedReader input = new BufferedReader(new InputStreamReader(client.getInputStream()));
                String serverResponse = input.readLine();
        
                System.out.println();
                System.out.println("Recevied ciphertext is: " + serverResponse); //Print encrypted text
            
                //the ciphertext, in hex, must be converted to bytes
                byte[] recvText = DatatypeConverter.parseHexBinary(serverResponse);
                
                try{
                    //Find the index that's the halfway point between the plaintext and the HMAC
                    get_Index = new Scanner(new File("Index.txt"));
                    int ind = get_Index.nextInt();
                    
                    String recvHMAC = decryption(recvText, writeDESKey, ind); //decrypt message to get concatenation
            
                    //Use index to break concatenation into two strings, one holds plaintext and the other holding the HMAC
                    String s1 = recvHMAC.substring(0, ind);
                    String s2 = recvHMAC.substring(ind);
            
                    //Verify the HMAC of recevied message is equal to newly constructed HMAC
                    verify(s1, s2);
                }catch(Exception e){
                    System.out.println("Exception.");
                }
            }
        }finally{
            //Close Socket and ServerSocket variables
            listener.close();
            client.close();
            console.close(); //Close Scanner
        }
    }
    
    //In method, get HMAC encryption of message, concatenated HMAC to plaintext message and encrypted the entire string using DES
    public static void encryption(String msg, PrintWriter p){
        String sentHMAC;
                
        try{
            byte []mac_key = HMAC_SHA_KEY.doFinal(msg.getBytes()); //HMAC encrypts plaintext message
            sentHMAC = Base64.getEncoder().encodeToString(mac_key); //convert secret kay variable to string
            System.out.println("Sender side HMAC is: " + sentHMAC); //print HMAC
            String str = msg.concat(sentHMAC); //Concatenation of plaintext message and HMAC
            //System.out.println("Concatenation is: " + str);
            
            //Ecrypt concatenaetd string using DES
            encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding"); //have Cipher variable encrypt using DES algorithm
            encrypt.init(Cipher.ENCRYPT_MODE, DES_KEY); //initialized Cipher variable to encrypt mode with secret key as parameter
            byte []text = str.getBytes();
            byte []ciphertext = encrypt.doFinal(text); //ecrypt text
            System.out.println("Sent cyphertext is: " + DatatypeConverter.printHexBinary(ciphertext)); //convert from bytes to Hex format
            p.println(DatatypeConverter.printHexBinary(ciphertext)); //Sent encrypted text (in Hex format) to Server
        }catch(Exception e){
            System.out.println();
        }
    }
    
    //decrypts message from client and splits concatenated string
    public static String decryption(byte []enMsg, String key, int i){        
        try{
            decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding"); //have Cipher variable encrypt using DES algorithm
            decrypt.init(Cipher.DECRYPT_MODE, DES_KEY); //initialized Cipher variable to encrypt mode with secret key as parameter
            byte []deMsg = decrypt.doFinal(enMsg); //ecrypt text
            String oriMsg = new String(deMsg); //convert byte array to string
            //Use index to break concatenation into two strings, one holds plaintext and the other holding the HMAC
            System.out.println("Received message is: " + oriMsg.substring(0, i)); //Split string to just show plaintext message
            //System.out.println("Concatenation is: " + oriMsg);
            System.out.println("Received HMAC is: " + oriMsg.substring(i)); //Split string to just show HMAC
            return oriMsg;
        }catch(NoSuchAlgorithmException e){ //handle multiple exceptions
            System.out.println("No such algorithm.");
        }catch(NoSuchPaddingException e){
            System.out.println("No such padding.");
        }catch(BadPaddingException e){
            System.out.println("Bad padding.");
        }catch(IllegalBlockSizeException e){
            System.out.println("Illegal block size.");
        }catch(IllegalArgumentException e){
            System.out.println("Illegal argument size.");
        }catch(InvalidKeyException e){
            System.out.println("Invalid key.");
        }catch(Exception e){
            System.out.println("Exception.");
        }
        
        return "";
    }
    
    //Method verifies that received HMAC and newly constructed HMAC are the same
    public static void verify(String s1, String s2){
        try{
            byte []mac_key = HMAC_SHA_KEY.doFinal(s1.getBytes()); //HMAC encrypts plaintext message
            String newHMAC = Base64.getEncoder().encodeToString(mac_key); //convert secret kay variable to string
            
            //Check to see if the HMACs are the same
            if(newHMAC.equals(s2)){
                System.out.println("Calculated HMAC is: " + newHMAC);
                System.out.println("HMAC Verified");
            }else
                System.out.println("Calculated HMAC is: " + newHMAC); //to check if HMACs are different
        
        }catch(Exception e){
            System.out.println("Exception in Verify method.");
        }
    }
}
