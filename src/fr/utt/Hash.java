package fr.utt;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash {

    //hash avec c comme BigInteger
    public static BigInteger monHash(BigInteger B1,BigInteger B2,BigInteger c) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest crypt = java.security.MessageDigest.getInstance("SHA-256");
        crypt.reset();
        //on hash la concatenation des 3 valeurs B1,B2,c
        crypt.update((B1.toString() + B2.toString() + c.toString()).getBytes("UTF-8"));
        //on récupère le hash sous forme binaire et on le recrée en objet BigInteger pour que cela soit plus simple
        byte[] betaByte = crypt.digest();
        return new BigInteger(betaByte);
    }

    //hash avec c comme string
    public static BigInteger monHash(BigInteger B1,BigInteger B2,String c) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest crypt = java.security.MessageDigest.getInstance("SHA-256");
        crypt.reset();
        //on hash la concatenation des 3 valeurs B1,B2,c
        crypt.update((B1.toString() + B2.toString() + c).getBytes("UTF-8"));
        //on récupère le hash sous forme binaire et on le recrée en objet BigInteger pour que cela soit plus simple
        byte[] betaByte = crypt.digest();
        return new BigInteger(betaByte);
    }

    //hash juste une string
    public static BigInteger monHash(String c) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest crypt = java.security.MessageDigest.getInstance("SHA-256");
        crypt.reset();
        crypt.update(c.getBytes("UTF-8"));
        //on récupère le hash sous forme binaire et on le recrée en objet BigInteger pour que cela soit plus simple
        byte[] betaByte = crypt.digest();
        return new BigInteger(betaByte);
    }
}
