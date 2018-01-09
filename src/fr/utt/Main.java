package fr.utt;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        Scanner scanner = new Scanner(System.in);
        CramerShoup cramerShoup = new CramerShoup();
        ThreeFish t = new ThreeFish();
        int reponse=0;

        System.out.println("Bienvenue dans notre Projet GS15 Léo Schneider/Marc Lanois\n");

        while(reponse!=7){
            System.out.println("Quelle action voulez vous faire ? \n" +
                    "1 : chiffrement symétrique\n" +
                    "2 : déchiffrement symétrique\n" +
                    "3 : génération de clés asymétrique\n" +
                    "4 : chiffrement asymétrique\n" +
                    "5 : déchiffrement asymétrique\n" +
                    "6 : hashage\n" +
                    "7 : quitter\n");

            reponse = scanner.nextInt();
            switch (reponse){
                case 1:
                    System.out.println("Sur quel taille de bloc voulez-vous chiffrer ? (256, 512 ou 1024 bits)");
                    int tailleChiffrer=scanner.nextInt();
                    System.out.println("Quel mode de chiffrement voulez-vous utiliser ? (1: ECB; 2: CBC)");
                    int mode1=scanner.nextInt();
                    t.ThreeFish(reponse, tailleChiffrer, mode1);
                    break;
                case 2:
                    System.out.println("Sur quel taille de bloc voulez-vous déchiffrer ? (256, 512 ou 1024 bits)");
                    int tailleDechiffrer=scanner.nextInt();
                    System.out.println("Quel mode de chiffrement voulez-vous utiliser ? (1: ECB; 2:CBC)");
                    int mode2=scanner.nextInt();
                    t.ThreeFish(reponse, tailleDechiffrer, mode2);
                    break;
                case 3:
                    System.out.println("Sur combien de bits voulez vous générer les clés ?");
                    int nbBits=scanner.nextInt();
                    cramerShoup.keygen(nbBits);
                    break;
                case 4:
                    cramerShoup.encrypt();
                    break;
                case 5:
                    cramerShoup.decrypt();
                    break;
                case 6:
                    System.out.println("Quel string voulez vous hash ?");
                    scanner.nextLine();
                    String stringToHash = scanner.nextLine();
                    System.out.println("Voici le hash de votre string :\n"+Hash.monHash(stringToHash));
                    break;
                default:break;
            }
        }
        System.out.println("Au revoir.");
    }
}
