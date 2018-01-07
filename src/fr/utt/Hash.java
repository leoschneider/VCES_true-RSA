package fr.utt;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class Hash {

    //hash avec c comme BigInteger
    public static BigInteger monHash(BigInteger B1,BigInteger B2,BigInteger c) throws NoSuchAlgorithmException {
        MessageDigest crypt = java.security.MessageDigest.getInstance("SHA-256");
        crypt.reset();

        //on hash la concatenation des 3 valeurs B1,B2,c
        crypt.update((B1.toString() + B2.toString() + c.toString()).getBytes());

        //on récupère le hash sous forme binaire et on le recrée en objet BigInteger pour que cela soit plus simple
        byte[] betaByte = crypt.digest();
        return new BigInteger(betaByte);
    }

    //hash avec c comme string
    public static BigInteger monHash(BigInteger B1,BigInteger B2,String c) throws NoSuchAlgorithmException{
        MessageDigest crypt = java.security.MessageDigest.getInstance("SHA-256");
        crypt.reset();
        //on hash la concatenation des 3 valeurs B1,B2,c
        crypt.update((B1.toString() + B2.toString() + c).getBytes());
        //on récupère le hash sous forme binaire et on le recrée en objet BigInteger pour que cela soit plus simple
        byte[] betaByte = crypt.digest();
        return new BigInteger(betaByte);
    }

    //hash avec c comme ArrayList de BigInteger (pour le hash de chiffrement)
    public static BigInteger monHash(BigInteger B1,BigInteger B2,ArrayList<BigInteger> arrayListC) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest crypt = java.security.MessageDigest.getInstance("SHA-256");
        crypt.reset();
        //on hash la concatenation des 3 valeurs B1,B2,c

        //on assemble les nombres entre eux
        crypt.update(B1.toString().getBytes());
        crypt.update(B2.toString().getBytes());
        for(BigInteger bg: arrayListC)
            crypt.update(bg.toString().getBytes());

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
