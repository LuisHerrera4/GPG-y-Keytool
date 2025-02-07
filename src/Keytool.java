import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

public class Keytool {


    public static void main(String[] args) {
        try {
            // Ejercicio 9: Generar par de claves en KeyStore
            generateKeyStorePair("keystore.p12", "password", "miAlias");

            // Ejercicio 11: Listar contenido del KeyStore
            listKeyStoreEntries("keystore.p12", "password");

            // Ejercicio 12: Crear otro par de claves con alias personalizado y validez de 90 días
            generateKeyStorePair("keystore_elteunom.ks", "password", "lamevaclauM9");

            // Ejercicio 13: Exportar clave pública
            exportPublicKeyFromKeyStore("keystore_elteunom.ks", "password", "lamevaclauM9", "certificado.asc");

            // Ejercicio 14: Firmar un archivo JAR
            signJar("miarchivo.jar", "keystore_elteunom.ks", "password", "lamevaclauM9", "miarchivo_firmado.jar");

            System.out.println("Operaciones de KeyStore completadas.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    // 1. Cifrar archivo con clave simétrica (AES)
    public static void encryptFileAES(String inputFilePath, String outputFilePath) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] inputBytes = Files.readAllBytes(new File(inputFilePath).toPath());
        byte[] encryptedBytes = cipher.doFinal(inputBytes);

        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(encryptedBytes);
        }

        // Guardar la clave para su posterior descifrado
        try (FileOutputStream keyOut = new FileOutputStream("aes.key")) {
            keyOut.write(secretKey.getEncoded());
        }
    }

    // 2. Cifrar archivo con 3DES (DESede)
    public static void encryptFile3DES(String inputFilePath, String outputFilePath) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
        keyGen.init(168);
        SecretKey secretKey = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("DESede");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] inputBytes = Files.readAllBytes(new File(inputFilePath).toPath());
        byte[] encryptedBytes = cipher.doFinal(inputBytes);

        try (FileOutputStream fos = new FileOutputStream(outputFilePath + ".3des")) {
            fos.write(encryptedBytes);
        }

        // Guardar la clave para su posterior descifrado
        try (FileOutputStream keyOut = new FileOutputStream("3des.key")) {
            keyOut.write(secretKey.getEncoded());
        }
    }

    // 3. Descifrar archivo cifrado (AES o 3DES)
    public static void decryptFile(String encryptedFilePath, String keyFilePath, String algorithm, String outputFilePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(keyFilePath).toPath());
        SecretKey secretKey = new SecretKeySpec(keyBytes, algorithm);

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] encryptedBytes = Files.readAllBytes(new File(encryptedFilePath).toPath());
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(decryptedBytes);
        }
    }

    // 4. Descifrar archivo simétrico recibido de un compañero (AES)
    public static void decryptReceivedFile(String encryptedFilePath, String keyFilePath, String outputFilePath) throws Exception {
        decryptFile(encryptedFilePath, keyFilePath, "AES", outputFilePath);
    }

    // 5. Generar un par de claves (RSA)
    public static void generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Guardar clave privada
        try (FileOutputStream fos = new FileOutputStream("private.key")) {
            fos.write(keyPair.getPrivate().getEncoded());
        }

        // Guardar clave pública
        try (FileOutputStream fos = new FileOutputStream("public.key")) {
            fos.write(keyPair.getPublic().getEncoded());
        }
    }

    // 6. Exportar clave pública a ASCII
    public static void exportPublicKeyToASCII(String publicKeyPath, String asciiOutputPath) throws Exception {
        byte[] publicKeyBytes = Files.readAllBytes(new File(publicKeyPath).toPath());
        String asciiKey = Base64.getEncoder().encodeToString(publicKeyBytes);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(asciiOutputPath))) {
            writer.write("-----BEGIN PUBLIC KEY-----\n");
            writer.write(asciiKey);
            writer.write("\n-----END PUBLIC KEY-----");
        }
    }

    // 7. Listar claves públicas en el sistema
    public static void listPublicKeys() {
        File dir = new File(".");
        File[] files = dir.listFiles((d, name) -> name.endsWith(".key") || name.endsWith(".asc"));

        if (files != null) {
            System.out.println("Claves públicas en el sistema:");
            for (File file : files) {
                System.out.println(file.getName());
            }
        } else {
            System.out.println("No se encontraron claves públicas.");
        }
    }

    // 8. Firmar un documento con la clave privada
    public static void signDocument(String documentPath, String privateKeyPath, String signatureOutputPath) throws Exception {
        byte[] privateKeyBytes = Files.readAllBytes(new File(privateKeyPath).toPath());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);

        byte[] documentBytes = Files.readAllBytes(new File(documentPath).toPath());
        signature.update(documentBytes);

        byte[] digitalSignature = signature.sign();

        try (FileOutputStream fos = new FileOutputStream(signatureOutputPath)) {
            fos.write(digitalSignature);
        }
    }

    // 9. Generar un par de claves usando KeyStore
    public static void generateKeyStorePair(String keyStorePath, String keyStorePassword, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, keyStorePassword.toCharArray());

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name x500Name = new X500Name("CN=Usuario, OU=Unidad, O=Organizacion, L=Ciudad, ST=Estado, C=Pais");
        CertAndKeyGen certGen = new CertAndKeyGen("RSA", "SHA256withRSA", null);
        certGen.setRandom(new SecureRandom());
        certGen.generate(2048);
        X509Certificate certificate = certGen.getSelfCertificate(x500Name, new Date(), (long) 365 * 24 * 60 * 60);

        keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyStorePassword.toCharArray(), new Certificate[]{certificate});

        try (FileOutputStream fos = new FileOutputStream(keyStorePath)) {
            keyStore.store(fos, keyStorePassword.toCharArray());
        }
    }

    // 11. Listar contenido del KeyStore
    public static void listKeyStoreEntries(String keyStorePath, String keyStorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keyStorePath)) {
            keyStore.load(fis, keyStorePassword.toCharArray());
        }

        System.out.println("Entradas en el KeyStore:");
        keyStore.aliases().asIterator().forEachRemaining(System.out::println);
    }

    // 13. Exportar clave pública desde KeyStore
    public static void exportPublicKeyFromKeyStore(String keyStorePath, String keyStorePassword, String alias, String outputPath) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keyStorePath)) {
            keyStore.load(fis, keyStorePassword.toCharArray());
        }

        Certificate cert = keyStore.getCertificate(alias);
        String encodedCert = Base64.getEncoder().encodeToString(cert.getEncoded());

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
            writer.write("-----BEGIN CERTIFICATE-----\n");
            writer.write(encodedCert);
            writer.write("\n-----END CERTIFICATE-----");
        }
    }

    // 14. Firmar un archivo JAR usando KeyStore
    public static void signJar(String jarFilePath, String keyStorePath, String keyStorePassword, String alias, String signedJarOutputPath) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keyStorePath)) {
            keyStore.load(fis, keyStorePassword.toCharArray());
        }

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyStorePassword.toCharArray());
        Certificate certificate = keyStore.getCertificate(alias);

        JarFile jarFile = new JarFile(jarFilePath);
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(signedJarOutputPath), jarFile.getManifest())) {
            jarFile.stream().forEach(entry -> {
                try {
                    jos.putNextEntry(new JarEntry(entry.getName()));
                    jarFile.getInputStream(entry).transferTo(jos);
                    jos.closeEntry();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(Files.readAllBytes(new File(jarFilePath).toPath()));

            byte[] digitalSignature = signature.sign();
            jos.putNextEntry(new JarEntry("META-INF/SIGNATURE.DSA"));
            jos.write(digitalSignature);
            jos.closeEntry();
        }
    }


}
