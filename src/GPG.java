import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class GPG {
    public static void main(String[] args) {
        try {
            // Ejercicio 1: Cifrar con AES
            encryptFileAES("archivo.txt", "archivo_cifrado_aes.txt");

            // Ejercicio 2: Cifrar con 3DES
            encryptFile3DES("archivo.txt", "archivo_cifrado");

            // Ejercicio 3: Descifrar el archivo 3DES
            decryptFile("archivo_cifrado.3des", "3des.key", "DESede", "archivo_descifrado.txt");

            // Ejercicio 4: Descifrar archivo recibido (AES)
            decryptReceivedFile("archivo_cifrado_companero.txt", "aes.key", "archivo_descifrado_companero.txt");

            // Ejercicio 5: Generar par de claves RSA
            generateKeyPair();

            // Ejercicio 6: Exportar clave pública a ASCII
            exportPublicKeyToASCII("public.key", "public_key.asc");

            // Ejercicio 7: Listar claves públicas
            listPublicKeys();

            // Ejercicio 8: Firmar un documento
            signDocument("archivo.txt", "private.key", "archivo_firmado.sig");

            System.out.println("Operaciones completadas.");
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

}
