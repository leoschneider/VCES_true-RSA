package fr.utt;

import java.math.BigInteger;
import java.util.Random;

public class CramerShoup {

    private Random random = new Random();

    private BigInteger[][] keygen(){

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

        BigInteger[] publicKey = new BigInteger[]{alfa1,alfa2,X,Y,W,p};
        BigInteger[] privateKey = new BigInteger[]{x1,x2,y1,y2,w,p};

        return new BigInteger[][]{privateKey,publicKey};
    }

    public String encrypt(String stringInput){
        return "";
    }

    public String decrypt(String stringInput){
        return "";
    }


}
