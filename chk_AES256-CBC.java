package aessimpleinterop;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// --- 30.01.2021 ---------------------------------------------------------
// Interoperable: OracleATP - Web Crypto API (JS) - Golang - Java - Python 
// Result: 01eb8015f319bda885939d265c4a38a0
// Friedhold Matz - 2021-JAN
// ------------------------------------------------------------------------

    public class AESsimpleInterop {
      private static String Key       = "12345678123456781234567812345678"; //32x8
      private static String IV        = "1234567812345678";
      private static String plaintext = "Hello, World!"; 

    // https://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
      
    public static byte[] encrypt(String plainText, String encryptionKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");       
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
        // 01eb8015f319bda885939d265c4a38a0
        return cipher.doFinal(plainText.getBytes("UTF-8"));
    }

    public static String decrypt(byte[] cipherText, String decryptionKey) throws Exception{
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(decryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
        return new String(cipher.doFinal(cipherText),"UTF-8");
    }

    // hex representation
    public static String bytes2Hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
    
    public static void main(String [] args) throws Exception {

        System.out.println("plain:   " + plaintext);

        byte[] cipher = encrypt(plaintext, Key);
        System.out.println(bytes2Hex(cipher));
         
        String decrypted = decrypt(cipher, Key);
        System.out.println("decrypt: " + decrypted);        
    }
}
