package fr.utt;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class CramerShoup {

    public  Scanner scanner = new Scanner(System.in);
    private Random random = new Random();

    public void keygen(int nbBits) throws IOException {

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

        //On (re)crée le fichier private.txt dans le répertoire du projet
        List<String> Privatelines= Arrays.asList(x1.toString(),x2.toString(),y1.toString(),y2.toString(),w.toString());
        Path privateFile = Paths.get("private.txt");
        Files.write(privateFile, Privatelines, Charset.forName("UTF-8"));

        //on (re)crée  le fichier public.txt dans le répertoire du projet
        List<String> PublicLines= Arrays.asList(p.toString(),alfa1.toString(),alfa2.toString(),X.toString(),Y.toString(),W.toString());
        Path publicFile = Paths.get("public.txt");
        Files.write(publicFile, PublicLines, Charset.forName("UTF-8"));

        System.out.println("Les fichiers de clés suivants ont bien été générés:\n     public.txt\n     private.txt\n");
    }

    public void encrypt() throws NoSuchAlgorithmException, UnsupportedEncodingException {

        BigInteger m = BigInteger.ONE;
        String mString;

        System.out.println("Quel type de fichier voulez vous travailler avec ? : \n" +
                "1 simple texte\n" +
                "2 fichier txt\n");
        int reponse = scanner.nextInt();
        scanner.nextLine();
        switch (reponse){
            case 1:
                //on récupère le texte à chiffrer :
                // mString est l'original, m est le nombre associé
                System.out.println("Entrez le texte que vous voulez chiffrer\n");
                mString = scanner.nextLine();
                m = new BigInteger(mString.getBytes());
                break;
            case 2:
                //on récupère un fichier
                try{
                    System.out.println("Veuillez indiquer votre fichier");
                    String FilePath = scanner.nextLine();
                    mString = new String(Files.readAllBytes(Paths.get(FilePath)));
                    m = new BigInteger(mString.getBytes());
                }catch(Exception e){
                    System.out.println(" |_!_| Erreur : Le fichier n'existe pas.");
                    return;
                }
                break;
            default:
                break;
        }

        //on lit les valeurs dans le fichier et les mets dans publicVals dans l'ordre p,alfa1,alfa2,X,Y,W
        ArrayList<BigInteger> recuperationFichier = monReadFile("Veuillez indiquer le fichier de votre clé publique",6);
        //on réassigne plus facilement les variables
        BigInteger p = recuperationFichier.get(0);
        BigInteger alfa1 = recuperationFichier.get(1);
        BigInteger alfa2 = recuperationFichier.get(2);
        BigInteger X = recuperationFichier.get(3);
        BigInteger Y = recuperationFichier.get(4);
        BigInteger W = recuperationFichier.get(5);

        //entier b aléatoire de chiffrement
        BigInteger b = new BigInteger(p.bitLength(),random).mod(p); //bitlength devrait marcher pour retrouver taille en bits

        //calcul des coefficients aux modulo p
        BigInteger B1 = alfa1.modPow(b,p);
        BigInteger B2 = alfa2.modPow(b,p);
        BigInteger c = W.modPow(b,p).multiply(m);

        //on crée le hash
        BigInteger beta = Hash.monHash(B1,B2,c);

        //v est la "vérification"
        BigInteger v = X.modPow(b,p).multiply((Y.modPow(b.multiply(beta),p))).mod(p);

        //on écrit un élément par ligne dans le fichier encrypted.txt ou on renvoie une erreur dans le cas échéant
        try {
            List<String> encryptedLines= Arrays.asList(B1.toString(),B2.toString(),c.toString(),v.toString());
            Path privateFile = Paths.get("encrypted.txt");
            Files.write(privateFile, encryptedLines, Charset.forName("UTF-8"));
            System.out.println(" -> Le fichier contenant le message chiffré est encrypted.txt\n");
        } catch (IOException e) {
            System.out.println(" |_!_| L'écriture du fichier encrypted.txt n'a pas fonctionné.\n");
            System.out.println("Le chiffré est : \n" +B1+"\n"+B2+"\n"+c+"\n"+v+"\n");
        }
    }

    public void decrypt() throws NoSuchAlgorithmException, UnsupportedEncodingException {

        ArrayList<BigInteger> recuperationFichier = monReadFile("Veuillez indiquer le fichier de votre clé privée",5);
        //on recrée ces variables pour que cela soit plus simple
        BigInteger x1 = recuperationFichier.get(0);
        BigInteger x2= recuperationFichier.get(1);
        BigInteger y1 = recuperationFichier.get(2);
        BigInteger y2 = recuperationFichier.get(3);
        BigInteger w = recuperationFichier.get(4);

        //On récupère juste p avec la clé publique..... bon....c'est pas très beau
        recuperationFichier = monReadFile("Veuillez indiquer le fichier de votre clé publique",1);
        BigInteger p = recuperationFichier.get(0);

        //meme idee cette fois ci pour recupérer les infos du fichier de déchiffrement
        recuperationFichier = monReadFile("quel fichier voulez vous déchiffrer?",4);
        BigInteger B1 = recuperationFichier.get(0);
        BigInteger B2 = recuperationFichier.get(1);
        BigInteger c = recuperationFichier.get(2);
        BigInteger v = recuperationFichier.get(3);

        //on crée le hash
        BigInteger betaPrime = Hash.monHash(B1,B2,c);

        //on calcule v' pour vérifier
        //on le calcule en plusieurs lignes pour que ce soit plus clair car on ne peut pas surcharger les opérateurs en java
        BigInteger vPrime = B1.modPow(x1,p).multiply(B2.modPow(x2,p)).mod(p);
        vPrime = vPrime.multiply( ( B1.modPow(y1,p).multiply(B2.modPow(y2,p)) ).modPow(betaPrime,p) ).mod(p);
        if(vPrime.compareTo(v)!=0) {
            System.out.println(" |_!_| Vérification échouée\n" + "Voici v1 :" + v + "\nVoici v2 :" + vPrime);
        }
        System.out.println("->Vérification réussie");
        BigInteger m = c.divide(B1.modPow(w,p)).mod(p);
        try {
            Path privateFile = Paths.get("output.txt");
            Files.write(privateFile, m.toByteArray());//, Charset.forName("UTF-8"));
            System.out.println("->le message complet a été écrit dans le fichier output.txt");
        } catch (IOException e) {
            System.out.println(" |_!_| L'écriture du fichier output.txt n'a pas fonctionné.\n");
        }
    }

    private BigInteger trouverGenerateurRandom(BigInteger p,int nbBits){
        do{
            //on cherche un nombre random plus petit que p mais sur nbBits bits
            //si il correspond à un générateur avec la formule alors on le prends sinon on continue
            BigInteger numTest;
            do{
                numTest = new BigInteger(nbBits,random);
            }while(numTest.compareTo(p)>0);
            if(numTest.modPow(p.subtract(BigInteger.ONE).divide(new BigInteger("2")), p).compareTo(BigInteger.ONE) > 0)
                return numTest;
        }while(true);
    }

    private ArrayList<BigInteger> monReadFile(String question,int nbLignes){
            ArrayList<BigInteger> a =new ArrayList<>();
        try{
            System.out.println(question);
            String publicFilePath = scanner.nextLine();
            FileReader fileReader = new FileReader(publicFilePath);
            BufferedReader buffer = new BufferedReader(fileReader);
            String lineRead;
            for(int i=0;i<nbLignes;++i){
                if( (lineRead = buffer.readLine()) != null)
                    a.add(new BigInteger(lineRead));
            }
        }catch(Exception e){
            System.out.println(" |_!_| Erreur : Le fichier n'existe pas.");
        }
        return a;
    }
}
