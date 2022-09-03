import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Assignment1 implements Assignment1Interface
{  

 //  public modulus (n) in hexadecimal
private static final BigInteger modulus = new BigInteger("c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9", 16);

    /// TAKEN IN THE PASSWORD ETC
public static void main(String[] args) throws NoSuchAlgorithmException, IOException {

 byte[] password = passwordToUTF8("sFxDmQ93ZNen9gl1"); // password in hex
 String filename = args[0]; // the file we want to work with
 File file = new File(filename);

byte[] salt = hexStringToByteArray("2b643f6d365b775824466d625c723567"); // 16 byte random value
byte[] IV = hexStringToByteArray("472f2a3775215e4d7a2c502b424d4372");


 BigInteger exponent = new BigInteger("65537"); // The encryption exponent (e) is 65537
 
 String path = file.getAbsolutePath();
 Path filepath = Paths.get(path);  // getting the file in 

 byte[] fileInBytes = Files.readAllBytes(filepath); // THE FILE IN BYTES

 // String printc = bytesToHex(fileInBytes); Did this to check what the file in hex should look like


 //System.out.println("The path of the file you want to work with is: " + filepath); // outputting the file

 Assignment1 c1 = new Assignment1();

 //byte[] encryptedPassword1 = passwordToUTF8(password); // converting the password to UTF8

 byte[] encryptedPassword = password;

 // THE ENCRYPTION KEY
 byte[] key = c1.generateKey(encryptedPassword,salt);

 //System.out.println("The password: " + password);

 // hashed 200 times using SHA-256.
 byte[] hashedKey = hashKey(key); // encrypted hash key


 // THESE ARE MY FINAL ONES
 byte[] encryptedAESText = c1.encryptAES(fileInBytes,IV, hashedKey);
 String encryptedTextHex = bytesToHex(encryptedAESText); // encrypted with AES


 // CHECKING DECRYPTED

 byte[] decryptedAESText = c1.decryptAES(encryptedAESText, IV, hashedKey);
 String decryptedAESHEX = bytesToHex(decryptedAESText);

//hashed 200 times using SHA-256.
 
 byte[] encryptedRSA = c1.encryptRSA(encryptedPassword, exponent, modulus); // RSA encryption
 String encryptedrsapassword = bytesToHex(encryptedRSA); // encrypted rsa password


 System.out.println(encryptedTextHex); // printing it out here so that it will go to > Encryption.txt

 // Writing the output to files
 BufferedWriter EncryptionOutput = null;
 BufferedWriter AESDecryptOutput = null;
 BufferedWriter EncryptedRSAOutput = null;
 BufferedWriter SaltOutput = null;
 BufferedWriter IVOutput = null;


    // WRITING DATA TO FILES
        try {
            //File EncryptionOutputFile = new File("Encryption.txt"); // AES ENCRYPTION
            File AESDecryptFile = new File("Decrypted.txt");
            File RSAEncryptFile = new File("Password.txt");
            File SaltFile = new File("Salt.txt");
            File IVFile = new File("IV.txt");

            //EncryptionOutput = new BufferedWriter(new FileWriter(EncryptionOutputFile));
            AESDecryptOutput = new BufferedWriter(new FileWriter(AESDecryptFile));
            EncryptedRSAOutput = new BufferedWriter(new FileWriter(RSAEncryptFile));
            SaltOutput = new BufferedWriter(new FileWriter(SaltFile));
            IVOutput = new BufferedWriter(new FileWriter(IVFile)); 
            
            //EncryptionOutput.write(encryptedTextHex);
            AESDecryptOutput.write(decryptedAESHEX);
            EncryptedRSAOutput.write(encryptedrsapassword); //encrypted aes password
            SaltOutput.write(bytesToHex(salt)); // put salt value
            IVOutput.write(bytesToHex(IV)); // put iv value

        } catch ( IOException e ) {
            System.out.println(e.getMessage());
        } finally {
           // EncryptionOutput.close();
            AESDecryptOutput.close();
            EncryptedRSAOutput.close();
            SaltOutput.close();
            IVOutput.close();
          
        }


    }

    // Converting hex string to a byte array

public static byte[] hexStringToByteArray(String s) {
    int strlen = s.length();

    byte[] arraystr = new byte[strlen / 2];

    for (int i = 0; i < strlen; i += 2) {

        arraystr[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));

    }
    return arraystr;
}

// CONVERTING BYTE TO HEX STRING

public static String getHexString (String s) 
{
    byte[] buf = s.getBytes();

    StringBuffer sb = new StringBuffer();

    for (byte b:buf)
    {
        sb.append(String.format("%x", b));
    }


        return sb.toString();
}

// converting bytes to hexadecimal

public static String bytesToHex(byte[] in) {

    final StringBuilder builder = new StringBuilder();

    for(byte b : in) {

        builder.append(String.format("%02x", b));
    }

    return builder.toString();
}

    @Override
    // generate the key by concating salt and password that is utf8 encoded

    public byte[] generateKey(byte[] password, byte[] salt) {
      
            byte[] key = new byte[password.length + salt.length];

            System.arraycopy(password, 0, key, 0, password.length);

            System.arraycopy(salt, 0, key, password.length, salt.length);

            return key;
        }

    // converting password to UTF8

    private static byte[] passwordToUTF8(String password) throws UnsupportedEncodingException

    {
        byte[] passBytes = password.getBytes("UTF-8");

        return passBytes;
    }


    @Override
    public byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key)
    {
        try 
        {
            IvParameterSpec IV = new IvParameterSpec(iv);

            SecretKeySpec AESkey = new SecretKeySpec(key, "AES");

            Cipher encryptor = Cipher.getInstance("AES/CBC/NoPadding");
            
            encryptor.init(Cipher.ENCRYPT_MODE, AESkey, IV);

          
            // PADDING AS SHOWN IN NOTES THE SECOND SCHEME
            int padding = 16 - (plaintext.length % 16);

            byte[] encrptpaddedfile = new byte[plaintext.length + padding];

		    System.arraycopy(plaintext, 0, encrptpaddedfile, 0, plaintext.length);		


		    encrptpaddedfile[plaintext.length] = (byte) 128;

		    for (int i = plaintext.length + 1; i < encrptpaddedfile.length; i++) 
            {
			    encrptpaddedfile[i] = (byte) 0;
		    }
    
            byte[] encryptedPaddedBytes = encryptor.doFinal(encrptpaddedfile);
        
            return encryptedPaddedBytes;
        }
        catch(Exception e)
        {
        
            System.out.println(e.getMessage());
            return plaintext;
        }
    }
    


    // USED FOR DECRYPTING, FOR TESTING I PRINT THE FILE OUT IN HEX IN THE Decrypted.txt file
    @Override
    public byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key) 
    {
        try 
            {
                IvParameterSpec IV = new IvParameterSpec(iv);

                SecretKeySpec AESkey = new SecretKeySpec(key, "AES");

                Cipher decryptor = Cipher.getInstance("AES/CBC/NoPadding");
                
                decryptor.init(Cipher.DECRYPT_MODE, AESkey, IV);
    
                byte[] plaintextBytes = decryptor.doFinal(ciphertext);
        
                return plaintextBytes;
            }
        catch(Exception e)
        {
            System.out.println(e.getMessage());
            return ciphertext;
        }
    }


    @Override
    public byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus)
    {
        BigInteger modularexpo = modExp(new BigInteger(plaintext), exponent, modulus);

        byte [] encrypedRSAPassword = modularexpo.toByteArray();

        return encrypedRSAPassword;

    }



    /*
        y = 1
        for i = 0 to k-1 do
            if xi = 1 then y = (y * a) mod n end if
            a = (a * a) mod n
        end
    */

   // right to left   

    // Modular exponentiation we could use the left to right variant or the right to left varient
    @Override
    public BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus)
    {
        BigInteger res = BigInteger.valueOf(1);
       
        for(int i = 0; i < exponent.bitLength(); i++)
        {
            if (exponent.testBit(i)) {

                res = res.multiply(base).mod(modulus);
            }

            base = base.multiply(base).mod(modulus);
        }

        return res;
    }

    // HASHING IT BY SHA-256
    
    private static byte[] hashKey(byte[] key) throws NoSuchAlgorithmException {

		MessageDigest md = MessageDigest.getInstance("SHA-256"); // Provides us the SHA-256 hash functions
        
        // HASHING IT 200 TIMES
		byte[] hashedKey = key;
		for (int i = 1; i <= 200; i++) {
			hashedKey = md.digest(hashedKey);
		}
		return hashedKey;
	}

}


//references: 
//  http://www.herongyang.com/Bitcoin/Block-Data-Calculate-Double-SHA256-with-Java.html
// https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/
// https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/
// https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
// https://stackoverflow.com/questions/2817752/java-code-to-convert-byte-to-hexadecimal