package fr.utt;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class CramerShoup {

    private Random random = new Random();
    private BigInteger[] privateKey; //il s'agit bien de tableaux de valeurs et pas d'une seule
    private BigInteger[] publicKey;

    public void keygen(int nbBits){

        BigInteger p = new BigInteger(nbBits,random); //on crée p random mais sur nbBits bits
        p = p.nextProbablePrime(); //p devient le prochain nombre probablement premier après p avec prb 2^-100

        BigInteger alfa1 = trouverGenerateurRandom(p,nbBits);
        BigInteger alfa2 = trouverGenerateurRandom(p,nbBits);

        BigInteger x1 = new BigInteger(nbBits,random);
        BigInteger x2 = new BigInteger(nbBits,random);
        BigInteger y1 = new BigInteger(nbBits,random);
        BigInteger y2 = new BigInteger(nbBits,random);
        BigInteger w = new BigInteger(nbBits,random);

        BigInteger X = (alfa1.modPow(x1,p)).multiply((alfa2.modPow(x2,p))).mod(p);
        BigInteger Y = (alfa1.modPow(y1,p)).multiply((alfa2.modPow(y2,p))).mod(p);
        BigInteger W = alfa1.modPow(w,p);

        publicKey = new BigInteger[]{p,alfa1,alfa2,X,Y,W};
        privateKey = new BigInteger[]{x1,x2,y1,y2,w};

        System.out.println("La clé privée est : \n"+x1+"\n"+x2+"\n"+y1+"\n"+y2+"\n"+w+"\n"+p+"\n\n");
        System.out.println("La clé publique est : \n"+alfa1+"\n"+alfa2+"\n"+X+"\n"+Y+"\n"+W+"\n"+p+"\n\n");
    }

    public BigInteger[] encrypt(int nbBits,BigInteger m,BigInteger[] myPublicKey) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        BigInteger alfa1 = myPublicKey[0];
        BigInteger alfa2 = myPublicKey[1];
        BigInteger X = myPublicKey[2];
        BigInteger Y = myPublicKey[3];
        BigInteger W = myPublicKey[4];
        BigInteger p = myPublicKey[5];

        BigInteger b = new BigInteger(nbBits,random);
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

        System.out.println("Le chiffré est : \n" +
                B1+"\n"+B2+"\n"+c+"\n"+v+"\n");
        return new BigInteger[]{B1,B2,c,v};
    }

    public String decrypt(String stringInput){
        return "";
    }

    private BigInteger trouverGenerateurRandom(BigInteger p,int nbBits){

        do{
            //on cherche un nombre random plus petit que p mais sur nbBits bits
            BigInteger numTest;
            do{
                numTest = new BigInteger(nbBits,random);
            }while(numTest.compareTo(p)>0);
            if(numTest.modPow(p.subtract(BigInteger.ONE).divide(new BigInteger("2")), p).compareTo(BigInteger.ONE) > 0)
                return numTest;
        }while(true);


    }

    //fonction qui sélectionne un générateur avec la liste des générateurs
    private BigInteger[] trouverGen(BigInteger p) {
        ArrayList<BigInteger> listeGen = creerListeGen(p,10000);
        Collections.shuffle(listeGen,random);
        return new BigInteger[]{listeGen.get(0),listeGen.get(1)};
    }

    private ArrayList<BigInteger> creerListeGen(BigInteger primeP,int tailleMax) {
        //tailleMax pour empécher le système de freeze en cherchant trop de générateurs
        ArrayList<BigInteger> generateurs = new ArrayList<>();
        BigInteger numTest = new BigInteger("2");
        BigInteger exponant = primeP.subtract(BigInteger.ONE).divide(new BigInteger("2"));
        do{
            if(numTest.modPow(exponant, primeP).compareTo(BigInteger.ONE) > 0 &&
                    numTest.compareTo(new BigInteger("100000000000000000000"))>0)
                //on cherche des générateurs pas trop petits d'ou 100000000000000000000
                generateurs.add(numTest);
            else
                generateurs.add(numTest.negate().mod(primeP));
            numTest = numTest.add(BigInteger.ONE);
        }while((--tailleMax > 0) && (numTest.compareTo(primeP.subtract(BigInteger.ONE)) < 0));
        return generateurs;
    }

    //fonction utilitaire de sqrt pour BigInteger
    public static BigInteger sqrt(BigInteger x) {
        BigInteger div = BigInteger.ZERO.setBit(x.bitLength()/2);
        BigInteger div2 = div;
        // Loop until we hit the same value twice in a row, or wind
        // up alternating.
        for(;;) {
            BigInteger y = div.add(x.divide(div)).shiftRight(1);
            if (y.equals(div) || y.equals(div2))
                return y;
            div2 = div;
            div = y;
        }
    }

    public BigInteger[] getPublicKey() {
        return publicKey;
    }


}
