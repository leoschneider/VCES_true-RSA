package fr.utt;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;

public class ThreeFish {

    //Tableaux de permutations
    private static final int[] P256 = {2, 0, 3, 1};

    private static final int[] PI256 = {1, 3, 0, 2};

    private static final int[] P512 = {2, 3, 1, 5, 6, 0, 7, 4};

    private static final int[] PI512 = {5, 2, 0, 1, 7, 3, 4, 6};

    private static final int[] P1024 = {12, 7, 10, 0, 2, 11, 4, 13, 5, 1, 3, 15, 14, 8, 9, 6};

    private static final int[] PI1024 = {3, 9, 4, 10, 6, 8, 15, 1, 13, 14, 2, 5, 0, 7, 12, 11};


    private static final int nbBits = 64;

    private static final int nbTournees = 76;

    private static BigInteger puissance = new BigInteger("2");

    private static final int numVI = 1;

    private int[] p;

    private int[] pi;

    private int tailleBlocs;

    //Constante C
    private static final byte cByte[] = {(byte)0x1B, (byte)0xD1, (byte)0x1B, (byte)0xDA, (byte)0xA9, (byte)0xFC, (byte)0x1A, (byte)0x22};

    public Scanner scanner = new Scanner(System.in);

    public void ThreeFish(int type, int choixBlocs, int mode) throws IOException, NoSuchAlgorithmException {
        String fichierMessage;
        String fichierCle;

        //Initialisation des paramètres
        parametresThreeFish(choixBlocs);

        //Récupération des fichiers
        System.out.println("Veuillez indiquer votre fichier de clé");
        fichierCle = scanner.nextLine();
        System.out.println("Veuillez indiquer votre fichier d'entrée");
        fichierMessage = scanner.nextLine();

        //Récupération des données contenues dans les fichiers
        byte[] message = lectureFichier(fichierMessage);
        byte[] cle = lectureFichier(fichierCle);

        //Test des longueurs des entrées
        testLongueurs(message, cle);

        //Cas où la taille de bloc choisie est identique à celle du message
        if (tailleBlocs == (message.length*8)){
            BigInteger[] messageConcatene = concatenation(message);
            BigInteger[] cleConcatenee = concatenation(cle);
            switch (type){
                case 1:
                    //Chiffrement du message et écriture du fichier
                    try {
                        ecritureFichier("messageChiffre.txt", chiffrement(messageConcatene, cleConcatenee));
                        System.out.println(" -> Le fichier contenant le message chiffré est messageChiffre.txt\n");
                    } catch (IOException e) {
                        System.out.println(" |_!_| L'écriture du fichier messageChiffre.txt n'a pas fonctionné.\n");
                    }
                    break;
                case 2:
                    //Déchiffrement du message et écriture du fichier
                    try {
                        ecritureFichier("messageDechiffre.txt", dechiffrement(messageConcatene, cleConcatenee));
                        System.out.println(" -> Le fichier contenant le message déchiffré est messageDechiffre.txt\n");
                    } catch (IOException e) {
                        System.out.println(" |_!_| L'écriture du fichier messageDechiffre.txt n'a pas fonctionné.\n");
                    }
                    break;
                default:
                    break;
            }
        }
        //Cas où la taille de bloc choisie est différente de celle du message
        else{
            //Division des données taille de bloc choisie
            byte[][] messageDivise = diviserDonnee(message);
            byte[][] cleDivisee = diviserDonnee(cle);
            switch (type){
                case 1:
                    switch (mode){
                        case 1:
                            //Chiffrement en mode ECB
                            chiffrementModeECB(messageDivise, cleDivisee, message.length, cle.length);
                            break;
                        case 2:
                            //Chiffrement en mode CBC
                            chiffrementModeCBC(messageDivise, cleDivisee, message.length, cle.length);
                            break;
                        default:
                            break;
                    }
                    break;
                case 2:
                    switch (mode){
                        case 1:
                            //Déchiffrement en mode ECB
                            dechiffrementModeECB(messageDivise, cleDivisee, message.length, cle.length);
                            break;
                        case 2:
                            //Déchiffrement en mode CBC
                            dechiffrementModeCBC(messageDivise, cleDivisee, message.length, cle.length);
                            break;
                        default:
                            break;
                    }
                    break;
                default:
                    break;
            }
        }
    }

    public void chiffrementModeECB(byte[][] messageDivise, byte[][] cleDivisee, int messageLength, int cleLength) throws IOException, NoSuchAlgorithmException {
        BigInteger[][] ensembleMessage = new BigInteger[messageLength*8/tailleBlocs][tailleBlocs/8];
        BigInteger[][] ensembleCle = new BigInteger[cleLength*8/tailleBlocs][tailleBlocs/8];
        BigInteger[] messageChiffre = new BigInteger[messageLength/8];
        //Chiffrement de chaque bloc
        for (int i=0; i<messageLength*8/tailleBlocs; ++i){
            ensembleMessage[i] = concatenation(messageDivise[i]);
            ensembleCle[i] = concatenation(cleDivisee[i]);
            ensembleMessage[i] = chiffrement(ensembleMessage[i], ensembleCle[i]);
            //Ajout des données de chaque bloc chiffré à une variable
            System.arraycopy(ensembleMessage[i], 0 ,messageChiffre, i*ensembleMessage[i].length, ensembleMessage[i].length);
        }
        //Ecriture du fichier de chiffrement
        try {
            ecritureFichier("messageChiffre.txt", messageChiffre);
            System.out.println(" -> Le fichier contenant le message chiffré est messageChiffre.txt\n");
        } catch (IOException e) {
            System.out.println(" |_!_| L'écriture du fichier messageChiffre.txt n'a pas fonctionné.\n");
        }
    }

    public void chiffrementModeCBC(byte[][] messageDivise, byte[][] cleDivisee, int messageLength, int cleLength) throws IOException, NoSuchAlgorithmException {
        BigInteger[][] ensembleMessage = new BigInteger[messageLength*8/tailleBlocs][tailleBlocs/8];
        BigInteger[][] ensembleCle = new BigInteger[cleLength*8/tailleBlocs][tailleBlocs/8];
        BigInteger[] messageChiffre = new BigInteger[messageLength/8];
        //Définition du vecteur d'initialisation
        BigInteger[] vi = concatenation(cleDivisee[numVI]);
        //Chiffrement de chaque bloc
        for (int i=0; i<messageLength*8/tailleBlocs; ++i){
            ensembleMessage[i] = concatenation(messageDivise[i]);
            //XOR entre le message clair et le vecteur
            for (int j=0; j<ensembleMessage[i].length; ++j){
                ensembleMessage[i][j] = ensembleMessage[i][j].xor(vi[j]);
            }
            ensembleCle[i] = concatenation(cleDivisee[i]);
            ensembleMessage[i] = chiffrement(ensembleMessage[i], ensembleCle[i]);
            //Ajout des données de chaque bloc chiffré à une variable
            System.arraycopy(ensembleMessage[i], 0 ,messageChiffre, i*ensembleMessage[i].length, ensembleMessage[i].length);
            vi = ensembleMessage[i];
        }
        //Ecriture du fichier de chiffrement
        try {
            ecritureFichier("messageChiffre.txt", messageChiffre);
            System.out.println(" -> Le fichier contenant le message chiffré est messageChiffre.txt\n");
        } catch (IOException e) {
            System.out.println(" |_!_| L'écriture du fichier messageChiffre.txt n'a pas fonctionné.\n");
        }
    }

    public void dechiffrementModeECB(byte[][] messageDivise, byte[][] cleDivisee, int messageLength, int cleLength) throws IOException, NoSuchAlgorithmException {
        BigInteger[][] ensembleMessage = new BigInteger[messageLength*8/tailleBlocs][tailleBlocs/8];
        BigInteger[][] ensembleCle = new BigInteger[cleLength*8/tailleBlocs][tailleBlocs/8];
        BigInteger[] messageDechiffre = new BigInteger[messageLength/8];
        //Déchiffrement de chaque bloc
        for (int i=0; i<messageLength*8/tailleBlocs; ++i){
            ensembleMessage[i] = concatenation(messageDivise[i]);
            ensembleCle[i] = concatenation(cleDivisee[i]);
            ensembleMessage[i] = dechiffrement(ensembleMessage[i], ensembleCle[i]);
            //Ajout des données de chaque bloc déchiffré à une variable
            System.arraycopy(ensembleMessage[i], 0 ,messageDechiffre, i*ensembleMessage[i].length, ensembleMessage[i].length);
        }
        //Ecriture du fichier de déchiffrement
        try {
            ecritureFichier("messageDechiffre.txt", messageDechiffre);
            System.out.println(" -> Le fichier contenant le message déchiffré est messageDechiffre.txt\n");
        } catch (IOException e) {
            System.out.println(" |_!_| L'écriture du fichier messageDechiffre.txt n'a pas fonctionné.\n");
        }
    }

    public void dechiffrementModeCBC(byte[][] messageDivise, byte[][] cleDivisee, int messageLength, int cleLength) throws IOException, NoSuchAlgorithmException {
        BigInteger[][] ensembleMessage = new BigInteger[messageLength*8/tailleBlocs][tailleBlocs/8];
        BigInteger[][] ensembleCle = new BigInteger[cleLength*8/tailleBlocs][tailleBlocs/8];
        BigInteger[] messageDechiffre = new BigInteger[messageLength/8];
        BigInteger[] vi;
        //Déchiffrement de chaque bloc
        for (int i=messageLength*8/tailleBlocs-1; i>=0; --i){
            ensembleMessage[i] = concatenation(messageDivise[i]);
            ensembleCle[i] = concatenation(cleDivisee[i]);
            ensembleMessage[i] = dechiffrement(ensembleMessage[i], ensembleCle[i]);
            //XOR entre le message déchiffré et le message chiffré du bloc précédent
            if (i != 0){
                for (int j=0; j<ensembleMessage[i].length; ++j){
                    vi = concatenation(messageDivise[i-1]);
                    ensembleMessage[i][j] = ensembleMessage[i][j].xor(vi[j]);
                }
            }
            else{
                for (int l=0; l<ensembleMessage[i].length; ++l){
                    ensembleMessage[i][l] = ensembleMessage[i][l].xor(ensembleCle[numVI][l]);
                }
            }
            //Ajout des données de chaque bloc déchiffré à une variable
            System.arraycopy(ensembleMessage[i], 0 ,messageDechiffre, i*ensembleMessage[i].length, ensembleMessage[i].length);
        }
        //Ecriture du fichier de déchiffrement
        try {
            ecritureFichier("messageDechiffre.txt", messageDechiffre);
            System.out.println(" -> Le fichier contenant le message déchiffré est messageDechiffre.txt\n");
        } catch (IOException e) {
            System.out.println(" |_!_| L'écriture du fichier messageDechiffre.txt n'a pas fonctionné.\n");
        }
    }

    //Définition des paramètres pour la taille de blocs et les tables de permutation
    public void parametresThreeFish(int tailleBloc) {
        switch (tailleBloc) {
            case 256:
                this.tailleBlocs = 256;
                this.p = P256;
                this.pi = PI256;
                break;
            case 512:
                this.tailleBlocs = 512;
                this.p = P512;
                this.pi = PI512;
                break;
            case 1024:
                this.tailleBlocs = 1024;
                this.p = P1024;
                this.pi = PI1024;
                break;
            default:
                throw new IllegalArgumentException("Taille de blocs invalide, cela doit être 256, 512 ou 1024 bits.");
        }
    }

    public BigInteger[][] calculCles(BigInteger[] cle){
        BigInteger c = new BigInteger(1, cByte);

        //Calcul de kn
        BigInteger[] kinit = new BigInteger[cle.length+1];
        for (int i=0; i<cle.length; ++i){
            kinit[i] = cle[i];
        }
        kinit[cle.length] = c;
        for(int i=0; i<cle.length-2; ++i){
            kinit[cle.length] = kinit[cle.length].xor(cle[i]);
        }

        //Calcul des tweaks (t0 et t1 correspondent à deux mots de la clé
        //définis selon la taille de celle-ci
        BigInteger[] t = new BigInteger[3];
        t[0] = cle[cle.length/2-1];
        t[1] = cle[cle.length-2];
        t[2] = t[0].xor(t[1]);


        //Calcul des clés pour chaque tournée
        BigInteger[][] ki = new BigInteger[20][cle.length];
        for (int i=0; i<20; ++i){
            for (int j=0; j<cle.length; ++j){
                if (j<=(cle.length-4)){
                    ki[i][j] = kinit[(i+j)%(cle.length+1)];
                }
                if (j==(cle.length-3)){
                    ki[i][j] = kinit[(i+j)%(cle.length+1)].add(t[i%3]).mod(puissance.pow(nbBits));
                }
                if (j==(cle.length-2)){
                    ki[i][j] = kinit[(i+j)%(cle.length+1)].add(t[(i+1)%3]).mod(puissance.pow(nbBits));
                }
                if (j==(cle.length-1)){
                    ki[i][j] = kinit[(i+j)%(cle.length+1)].add(BigInteger.valueOf(i).mod(puissance.pow(nbBits)));
                }
            }
        }
        return ki;
    }

    //Rotation circulaire vers la gauche
    public BigInteger rotationCirculaireGauche(BigInteger m, int nbRotations) {
        BigInteger ret = m;
            for(int i=0; i<nbRotations; ++i){
                ret = ret.shiftLeft(1);
                if (ret.testBit(64)) {
                    ret = ret.clearBit(64).setBit(0);
                }
            }
        return ret;
    }

    //Rotation circulaire vers la droite
    public BigInteger rotationCirculaireDroite(BigInteger m, int nbRotations) {
        BigInteger ret = m;
        for(int i=0; i<nbRotations; ++i){
            if (ret.testBit(0)) {
                ret = ret.clearBit(0).setBit(64);
            }
            ret = ret.shiftRight(1);
        }
        return ret;
    }

    //Mix de deux mots
    public BigInteger[] mix(BigInteger m1, BigInteger m2) {
        BigInteger[] mPrime = new BigInteger[2];
        mPrime[0] = (m1.add(m2)).mod(puissance.pow(64));
        mPrime[1] = mPrime[0].xor(rotationCirculaireGauche(m2, 49));

        return mPrime;
    }

    //Fonction inverse de mix de deux mot
    public BigInteger[] demix(BigInteger mPrime1, BigInteger mPrime2) {
        BigInteger[] m = new BigInteger[2];
        m[1] = rotationCirculaireDroite(mPrime1.xor(mPrime2), 49);
        m[0] = (mPrime1.subtract(m[1])).mod(puissance.pow(64));
        return m;
    }

    //Division de la donnée en mots de 64 bits
    public BigInteger[] concatenation(byte[] donnee){
        BigInteger[] concatene = new BigInteger[donnee.length/8];
        for (int i=0, j=0; i<donnee.length; i+=8, ++j){
            byte destination[] = {donnee[i], donnee[i+1], donnee[i+2], donnee[i+3], donnee[i+4], donnee[i+5], donnee[i+6], donnee[i+7]};
            concatene[j]= new BigInteger(1, destination);
        }
        return concatene;
    }

    //Division de la donnée en bloc de taille choisie
    public byte[][] diviserDonnee(byte[] donnee){
        int rapport = donnee.length*8/tailleBlocs;
        int nombreElements = tailleBlocs/8;
        byte[][] donneeDivisee = new byte[rapport][nombreElements];
        for (int i=0; i<rapport; ++i){
            System.arraycopy(donnee, i*nombreElements ,donneeDivisee[i], 0, nombreElements);
        }
        return donneeDivisee;
    }

    //Récuération des données du fichier indiqué
    public byte[] lectureFichier(String nom) throws IOException, NoSuchAlgorithmException {
        Path inputFile = Paths.get(nom);
        byte[] data = Files.readAllBytes(inputFile);
        return data;
    }

    //Ecriture du fichier avec les données entrées
    public void ecritureFichier(String nom, BigInteger[] donnees) throws IOException, NoSuchAlgorithmException {
        Path outputFile = Paths.get(nom);
        Files.write(outputFile,"".getBytes());
        for(BigInteger a: donnees){
            byte[] readInter = a.toByteArray();
            if (readInter.length == 9){
                readInter = Arrays.copyOfRange(readInter, 1, 9);
            }
            Files.write(outputFile,readInter, StandardOpenOption.APPEND);
        }
    }

    //Test de longueur entre message et clé
    public void testLongueurs(byte[] message, byte[] cle){
        if(message.length == cle.length && message.length*8 % tailleBlocs == 0){
        }
        else{
            System.out.println("Les fichiers ne sont pas de la même taille et/ou La taille de bloc n'est pas compatible");
            System.exit(0);
        }
    }

    //Lancement des 76 tournées de chiffrement
    public BigInteger[] chiffrement(BigInteger[] message, BigInteger[] cle){
        //BigInteger[] messageChiffre = new BigInteger[message.length];
        if(message.length == cle.length){
            //Clacul des clés
            BigInteger[][] cles = calculCles(cle);

            //76 tournées
            for (int i=0; i<nbTournees/4; ++i){
                //XOR entre la clé et le message obtenu
                for (int j=0; j<message.length; ++j){
                    message[j] = message[j].xor(cles[i][j]);
                }

                //Tournée
                tournee(tournee(tournee(tournee(message))));
            }
            //XOR final entre la clé et le message obtenu
            for (int i=0; i<message.length; ++i){
                message[i] = message[i].xor(cles[19][i]);
            }
        }
        return message;
    }

    //Lancement des 76 tournées de déchiffrement
    public BigInteger[] dechiffrement(BigInteger[] message, BigInteger[] cle){
        //BigInteger[] messageChiffre = new BigInteger[message.length];
        if(message.length == cle.length){
            //Clacul des clés
            BigInteger[][] cles = calculCles(cle);

            //76 tournées
            for (int i=nbTournees/4; i>0; --i){
                //XOR entre la clé et le message obtenu
                for (int j=0; j<message.length; ++j){
                    message[j] = message[j].xor(cles[i][j]);
                }
                //Tournée
                tourneeInverse(tourneeInverse(tourneeInverse(tourneeInverse(message))));
            }
            //XOR final entre la clé et le message obtenu
            for (int i=0; i<message.length; ++i){
                message[i] = message[i].xor(cles[0][i]);
            }
        }
        return message;
    }

    //Tournée composée d'un mix pour chaque paire de mots et d'une permutation
    public BigInteger[] tournee(BigInteger[] message){
        //Mix des paires de mots
        BigInteger[] partiel = new BigInteger[2];
        for(int i=0; i<message.length/2; i+=2){
            partiel = mix(message[i], message[i+1]);
            message[i] = partiel[0];
            message[i+1] = partiel[1];
        }
        //Permutation du message
        permutation(message, p);
        return message;
    }

    //Tournée inverse composée d'une permutation et d'un démix de chaque paire de mots
    public BigInteger[] tourneeInverse(BigInteger[] message){
        //Permutation du message
        permutation(message, pi);

        //Demix des paires de mots
        BigInteger[] partiel;
        for(int i=0; i<message.length/2; i+=2){
            partiel = demix(message[i], message[i+1]);
            message[i] = partiel[0];
            message[i+1] = partiel[1];
        }
        return message;
    }

    //Permutation des données selon les indexes en entrée
    public BigInteger[] permutation(BigInteger[] message, int[] indexesPermutation){

        BigInteger[] messageSave = new BigInteger[message.length];
        for (int i=0; i<message.length; ++i){
            messageSave[i] = message[i];
        }
        for (int i=0; i<message.length; ++i) {
            message[indexesPermutation[i]] = messageSave[i];
        }
        return message;
    }
}
