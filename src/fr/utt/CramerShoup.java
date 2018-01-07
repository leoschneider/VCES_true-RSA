package fr.utt;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class CramerShoup {

    private  Scanner scanner = new Scanner(System.in);
    private Random random = new Random();

    public void keygen(int nbBits) throws IOException {

        BigInteger p = new BigInteger(nbBits,random); //on crée p random mais sur nbBits bits
        p = p.nextProbablePrime(); //p devient le prochain nombre probablement premier après p avec prb 2^-100

        //on trouve 2 générateurs
        BigInteger alfa1 = trouverGenerateurRandom(p,nbBits);
        BigInteger alfa2 = trouverGenerateurRandom(p,nbBits);

        //on détermine nos variables sur nbBits
        BigInteger x1 = new BigInteger(nbBits,random);
        BigInteger x2 = new BigInteger(nbBits,random);
        BigInteger y1 = new BigInteger(nbBits,random);
        BigInteger y2 = new BigInteger(nbBits,random);
        BigInteger w = new BigInteger(nbBits,random);

        BigInteger X = (alfa1.modPow(x1,p)).multiply((alfa2.modPow(x2,p))).mod(p);
        BigInteger Y = (alfa1.modPow(y1,p)).multiply((alfa2.modPow(y2,p))).mod(p);
        BigInteger W = alfa1.modPow(w,p);

        //On (re)crée le fichier pr.txt dans le répertoire du projet (clé privée)
        List<String> Privatelines= Arrays.asList(x1.toString(),x2.toString(),y1.toString(),y2.toString(),w.toString());
        Path privateFile = Paths.get("pr.txt");
        Files.write(privateFile, Privatelines, Charset.forName("UTF-8"));

        //on (re)crée  le fichier pu.txt dans le répertoire du projet (clé publique)
        List<String> PublicLines= Arrays.asList(p.toString(),alfa1.toString(),alfa2.toString(),X.toString(),Y.toString(),W.toString());
        Path publicFile = Paths.get("pu.txt");
        Files.write(publicFile, PublicLines, Charset.forName("UTF-8"));

        System.out.println("Les fichiers de clés suivants ont bien été générés:\n     pu.txt\n     pr.txt\n");
    }

    public void encrypt() throws NoSuchAlgorithmException, IOException {

        BigInteger m;
        ArrayList<BigInteger> chunks = new ArrayList<>();

        //on lit les valeurs dans le fichier et les mets dans publicVals dans l'ordre p,alfa1,alfa2,X,Y,W
        ArrayList<BigInteger> recuperationFichier = monReadFile("Veuillez indiquer le fichier de votre clé publique",6);

        //on réassigne plus facilement les variables
        BigInteger p = recuperationFichier.get(0);
        BigInteger alfa1 = recuperationFichier.get(1);
        BigInteger alfa2 = recuperationFichier.get(2);
        BigInteger X = recuperationFichier.get(3);
        BigInteger Y = recuperationFichier.get(4);
        BigInteger W = recuperationFichier.get(5);

        //on récupère le fichier
        try{
            System.out.println("Veuillez indiquer votre fichier à chiffrer.");
            String FilePath = scanner.nextLine();

            //on récupère les bytes
            byte[] inputBytes = Files.readAllBytes(Paths.get(FilePath));
            int chunkSize = p.bitLength()-1;

            //on assigne les blocs en fonction de la taille de clé
            for(int i=0;i<inputBytes.length;i+=chunkSize){                                                            //original découpement blocs
                byte[] bytesBlocs = Arrays.copyOfRange(inputBytes, i, Math.min(inputBytes.length - 1, i+chunkSize));
                chunks.add(new BigInteger(bytesBlocs));
            }
        }catch(Exception e){
            System.out.println(" |_!_| Erreur : "+e.getMessage());
            return;
        }


        //les morceaux chiffrés
        ArrayList<BigInteger> cChunks = new ArrayList<>();

        //entier b aléatoire de chiffrement
        BigInteger b = new BigInteger(p.bitLength(),random).mod(p); //bitlength devrait marcher pour retrouver taille en bits

        //calcul des coefficients aux modulo p
        BigInteger B1 = alfa1.modPow(b,p);
        BigInteger B2 = alfa2.modPow(b,p);
        for(BigInteger mChunk : chunks){
            cChunks.add(W.modPow(b,p).multiply(mChunk));
        }

        //on crée le hash
        BigInteger beta = Hash.monHash(B1,B2,cChunks);

        //v est la "vérification"
        BigInteger v = X.modPow(b,p).multiply((Y.modPow(b.multiply(beta),p))).mod(p);

        //on écrit un élément par ligne dans le fichier e.txt ou on renvoie une erreur dans le cas échéant
        try {
            //ecriture paramètres
            StringBuilder allChunksToStringParam = new StringBuilder();
            List<String> encryptedLinesParam = Arrays.asList(B1.toString(),B2.toString(),v.toString());
            Path paramFile = Paths.get("p.txt");
            Files.write(paramFile, encryptedLinesParam, Charset.forName("UTF-8"));
            System.out.println(" -> Le fichier contenant les paramètres est p.txt\n");

            //écriture fichier chiffré
            StringBuilder allChunksToString = new StringBuilder();
            for(BigInteger chunkNumber : cChunks)
                allChunksToString.append(chunkNumber.toString()).append("\n");                                                  //on met des retours ligne pour les blocs entre eux
            List<String> encryptedLines= Collections.singletonList(allChunksToString.toString());
            Path privateFile = Paths.get("e.txt");
            Files.write(privateFile, encryptedLines, Charset.forName("UTF-8"));
            System.out.println(" -> Le fichier contenant le message chiffré est e.txt\n");
        } catch (IOException e) {
            System.out.println(" |_!_| L'écriture du fichier e.txt n'a pas fonctionné.\n");
        }
    }

    public void decrypt() throws NoSuchAlgorithmException, IOException {
        ArrayList<BigInteger> recuperationFichier = monReadFile("Veuillez indiquer le fichier de votre clé privée",5);

        //on recrée ces variables pour que cela soit plus simple
        BigInteger x1 = recuperationFichier.get(0);
        BigInteger x2 = recuperationFichier.get(1);
        BigInteger y1 = recuperationFichier.get(2);
        BigInteger y2 = recuperationFichier.get(3);
        BigInteger w = recuperationFichier.get(4);

        //On récupère juste p avec la clé publique
        recuperationFichier = monReadFile("Veuillez indiquer le fichier de votre clé publique",1);
        BigInteger p = recuperationFichier.get(0);

        //meme idee cette fois ci pour recupérer les infos du fichier de déchiffrement
        recuperationFichier = monReadFile("quel fichier contient les paramètres à déchiffrer ?",4);
        BigInteger B1 = recuperationFichier.get(0);
        BigInteger B2 = recuperationFichier.get(1);
        BigInteger v = recuperationFichier.get(2);

        System.out.println("quel fichier voulez vous déchiffrer?");
        String locationFichier = scanner.nextLine();
        Path fileLocation = Paths.get(locationFichier);
        byte[] allBytesC = Files.readAllBytes(fileLocation);

        String text = new String(allBytesC);

        //on lit les blocks ligne par ligne
        ArrayList<String> stringBlocks = new ArrayList<>();
        Scanner blockReader = new Scanner(text);
        while(blockReader.hasNextLine()){
            stringBlocks.add(blockReader.nextLine());
        }
        stringBlocks.remove(stringBlocks.size()-1); //la dernière est toujours vide

        //séparer le message chiffré en blocs dans une arrayList
        ArrayList<BigInteger> cChunks = new ArrayList<>();
        for(String s : stringBlocks)
            cChunks.add(new BigInteger(s));

        //on crée le hash
        BigInteger betaPrime = Hash.monHash(B1,B2, cChunks);

        //on calcule v' pour vérifier
        //on le calcule en plusieurs lignes pour que ce soit plus clair car on ne peut pas surcharger les opérateurs en java
        BigInteger vPrime = B1.modPow(x1,p).multiply(B2.modPow(x2,p)).mod(p);
        vPrime = vPrime.multiply( ( B1.modPow(y1,p).multiply(B2.modPow(y2,p)) ).modPow(betaPrime,p) ).mod(p);
        if(vPrime.compareTo(v)!=0) {
            System.out.println(" |_!_| Vérification échouée\n" + "Voici v1 :" + v + "\nVoici votre v :" + vPrime);
        }else{
            System.out.println("-> Vérification réussie");
        }

        //déchiffrer les blocs
        ArrayList<BigInteger> mChunks = new ArrayList<>();
        for(BigInteger c :cChunks){
            BigInteger intermediaire = c.divide(B1.modPow(w,p));
            mChunks.add(intermediaire);
        }

        //écriture du message dans la console
        System.out.println("-> Voici le message en clair : ");
        for(BigInteger bigInteger : mChunks){
            System.out.println(new String(bigInteger.toByteArray()));
        }
        //ligne vide
        System.out.println("");

        //ecrire dans le fichier o.txt le message en clair déchiffré
        try {
            Path outputFile = Paths.get("o.txt");
            Files.write(outputFile,"".getBytes());
            //écriture bloc par bloc
            for(BigInteger bg:mChunks){
                byte[] readInter = bg.toByteArray();
                Files.write(outputFile,readInter, StandardOpenOption.APPEND);
            }
            System.out.println("->le message complet a été écrit dans le fichier o.txt\n");
        } catch (IOException e) {
            System.out.println(" |_!_| L'écriture du fichier o.txt n'a pas fonctionné."+e.getMessage()+"\n");
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
        ArrayList<BigInteger> a = new ArrayList<>();
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
            System.out.println(" |_!_| Erreur : "+e.getMessage());
        }
        return a;
    }
}