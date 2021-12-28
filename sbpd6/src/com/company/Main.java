package com.company;

import java.io.UnsupportedEncodingException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Main {

    private static SecretKeySpec secretKey;
    private static byte[] key;

    public static void main(String[] args)
    {
        final String secretKey = "quitebequiteplease";

        String originalString = "HelyaIsTheBest@gmail.com";
        String encryptedString = Main.encrypt(originalString, secretKey) ;
        String decryptedString = Main.decrypt(encryptedString, secretKey) ;

        System.out.println("Origin: " + originalString);
        System.out.println("Encrypted" + encryptedString);
        System.out.println("Decrypted" + decryptedString);
    }

    public static void setKey(String myKey)
    {
        try {
            key = MessageDigest.getInstance("SHA-1").digest(myKey.getBytes("UTF-8"));
            key = Arrays.copyOf(myKey.getBytes("UTF-8"), 16);
            secretKey = new SecretKeySpec(myKey.getBytes("UTF-8"), "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String strToEncrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        }
        catch (Exception e)
        {
            System.out.println("Encryption failed due to: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e)
        {
            System.out.println("Decryption failed due to: " + e.toString());
        }
        return null;
    }
}