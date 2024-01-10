package hmac;

import static hmac.Client.SERVER_IP;
import static hmac.Client.SERVER_PORT;
import static hmac.Client.encryption;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Server {
    
    //two variables needed for socket programming
    public static final String SERVER_IP = "localhost";
    public static final int SERVER_PORT = 9001;
    
    private static Cipher encrypt; //encryption cipher
    private static Cipher decrypt; //decryption cipher
    
    private static SecretKey DES_KEY; //secret key for DES
    private static Mac HMAC_SHA_KEY; //secret key for HMAC
    
    public static void main(String args[]) throws IOException{
        Scanner get_DES_file, get_HMAC_file; //scanner variables to read from key files
        Scanner console = new Scanner(System.in); //Reads input from Server
        String read_DES_key = "", read_HMAC_key = "";
        PrintStream index; //To create file to hold the length of message string
        Scanner get_Index; //To scan the index from shared file to split concatenation
        
        Socket s = new Socket(SERVER_IP, SERVER_PORT); //establish socket connection with the server
        
        try{
            //Find shared Key files
            get_DES_file = new Scanner(new File("DESKey.txt"));
            get_HMAC_file = new Scanner(new File("HMACKey.txt"));
            
            //Read from Key files
            read_DES_key = get_DES_file.nextLine();
            read_HMAC_key = get_HMAC_file.nextLine();
            
            //Close Scanner files
            get_DES_file.close();
            get_HMAC_file.close();
        }catch(Exception e){
            System.out.println("File not found.");
        }
        
        try{
            while(true){
                //Read from client's encrypted message
                BufferedReader input = new BufferedReader(new InputStreamReader(s.getInputStream()));
                String clientResponse = input.readLine();
                
                if(clientResponse == null) break; //If client's response is null, break out of loop
            
                System.out.println();
                System.out.println("Recevied ciphertext is: " + clientResponse); //Print encrypted text
            
                //the ciphertext, in hex, must be converted to bytes
                byte[] recvText = DatatypeConverter.parseHexBinary(clientResponse);
                
                try{
                    //Find the index that's the halfway point between the plaintext and the HMAC
                    get_Index = new Scanner(new File("Index.txt"));
                    int ind = get_Index.nextInt();
                    
                    String recvHMAC = decryption(recvText, read_DES_key, ind); //decrypt message to get concatenation
            
                    //Use index to break concatenation into two strings, one holds plaintext and the other holding the HMAC
                    String s1 = recvHMAC.substring(0, ind);
                    String s2 = recvHMAC.substring(ind);
            
                    //Setup Mac variable
                    HMAC_SHA_KEY = Mac.getInstance("HmacSHA256"); //get instance of Mac variable
                    HMAC_SHA_KEY.init(new SecretKeySpec(read_HMAC_key.getBytes(), "HmacSHA256")); //initialize Mac variable
            
                    verify(s1, s2); //Verify the HMAC of recevied message is equal to newly constructed HMAC
                }catch(InputMismatchException e){
                    System.out.println("Exception.");
                }catch(Exception e){
                    System.out.println("Exception.");
                }
        
                System.out.println();
                PrintWriter output = new PrintWriter(s.getOutputStream(), true);
                String m2 = console.nextLine();
                
                 //Place length of message into newly declared Index file
                index = new PrintStream(new File("Index.txt"));
                index.println(m2.length());
        
            //display shared keys and user input
                System.out.println();
                System.out.println("Shared DES Key is: " + read_DES_key);
                System.out.println("Shared HMAC Key is: " + read_HMAC_key);
                System.out.println("Plain message is: " + m2);
        
                encryption(m2, output); //call encryption method
            }
        }finally{
            s.close(); //Close Socket
            console.close(); //Close Scanner
        }
    }
    
    //decrypts message from client and splits concatenated string
    public static String decryption(byte []enMsg, String key, int i){
        byte []b = Base64.getDecoder().decode(key); //convert string to secret key variable
        DES_KEY = new SecretKeySpec(b, 0, b.length, "DES"); //initialize secret key variable
        
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
}
