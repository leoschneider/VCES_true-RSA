package fr.utt;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class CramerShoup {

    private Random random = new Random();
    private BigInteger[] privateKey;
    private BigInteger[] publicKey;

    private void keygen(){

        BigInteger p = new BigInteger(128,random);
        //on crée p random mais sur 128 bits
        BigInteger alfa1 = new BigInteger(128, random);
        BigInteger alfa2 = new BigInteger(128, random);
        while(alfa1.compareTo(p)>-1 || alfa1.compareTo(new BigInteger("2"))<1)
            alfa1 = new BigInteger(128,random);

        while(alfa2.compareTo(p)>-1 || alfa2.compareTo(new BigInteger("2"))<1)
            alfa2 = new BigInteger(128,random);

        //déterminer alfa 1 et 2 et si ils peuvent être des générateurs

        BigInteger x1 = new BigInteger(128,random);
        BigInteger x2 = new BigInteger(128,random);
        BigInteger y1 = new BigInteger(128,random);
        BigInteger y2 = new BigInteger(128,random);
        BigInteger w = new BigInteger(128,random);

        BigInteger X = (alfa1.modPow(x1,p)).multiply((alfa2.modPow(x2,p)));
        BigInteger Y = (alfa1.modPow(y1,p)).multiply((alfa2.modPow(y2,p)));
        BigInteger W = alfa1.modPow(w,p);

        publicKey = new BigInteger[]{alfa1,alfa2,X,Y,W,p};
        privateKey = new BigInteger[]{x1,x2,y1,y2,w,p};
    }

    public BigInteger[] encrypt(BigInteger m,BigInteger[] myPublicKey) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        BigInteger alfa1 = myPublicKey[0];
        BigInteger alfa2 = myPublicKey[1];
        BigInteger X = myPublicKey[2];
        BigInteger Y = myPublicKey[3];
        BigInteger W = myPublicKey[4];
        BigInteger p = myPublicKey[5];

        BigInteger b = new BigInteger(128,random);
        b = b.mod(p);

        BigInteger B1 = alfa1.modPow(b,p);
        BigInteger B2 = alfa2.modPow(b,p);
        BigInteger c = W.modPow(b,p).multiply(m);


        MessageDigest crypt = MessageDigest.getInstance("SHA-256");
        crypt.reset();
        crypt.update((c.toString()+B1.toString()+B2.toString()).getBytes("UTF-8"));
        byte[] betaByte = crypt.digest();
        BigInteger beta = new BigInteger(betaByte);

        BigInteger v = X.modPow(b,p).multiply((Y.modPow(b.multiply(beta),p)));

        return new BigInteger[]{B1,B2,c,v};
    }

    public String decrypt(String stringInput){
        return "";
    }


}
