import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class FinalTry {
    private static String node_rsa_init = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static void main(String[] args) throws Exception {
        // Generate a new RSA key pair
      /*  KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();*/

        // Get the public key



       // System.out.println("Public key:");
        //System.out.println("Modulus: " + rsaPublicKey.getModulus().toString(16));
       // System.out.println("Exponent: " + rsaPublicKey.getPublicExponent().toString(16));

        // Encrypt a long string in small chunks using the public key
        String longString = "{\"statusType\":\"OK\",\"entity\":[{\"customerStatusId\":2,\"customerStatusName\":\"Data Received\",\"customerStatusDescription\":\"Data Received\"},{\"customerStatusId\":3,\"customerStatusName\":\"Data Verification In Progress\",\"customerStatusDescription\":\"Data Verification In Progress\"},{\"customerStatusId\":5,\"customerStatusName\":\"Data Verification Failed\",\"customerStatusDescription\":\"Data Verification Failed\"},{\"customerStatusId\":7,\"customerStatusName\":\"Credit Approved\",\"customerStatusDescription\":\"Credit Approved\"},{\"customerStatusId\":16,\"customerStatusName\":\"Temporary Block\",\"customerStatusDescription\":\"Temporary Block\"},{\"customerStatusId\":11,\"customerStatusName\":\"Permanent Block\",\"customerStatusDescription\":\"Permanent Block\"}],\"entityType\":\"java.util.ArrayList\",\"metadata\":{},\"status\":200}";
        byte[] encryptedString = encryptWithPublicKey(longString);

        // Print the encrypted string in Base64 format
        System.out.println("Encrypted string:");
        System.out.println(Base64.getEncoder().encodeToString(encryptedString));

        // Decrypt the encrypted string using the private key
        String decryptedString = decryptWithPrivateKey(encryptedString);

        System.out.println("Decrypted string:");
        System.out.println(decryptedString);
    }

    public static byte[] encryptWithPublicKey(String plaintext) throws Exception {
        // Create a cipher object using the public key and encryption algorithm
        //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        Cipher cipher = Cipher.getInstance(node_rsa_init);
        PublicKey publicKey = readPublicKeyFromPem();

        cipher.init(Cipher.ENCRYPT_MODE, publicKey,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));


        // Divide the plaintext into smaller chunks of a fixed size
        int blockSize = 117;
        byte[] buffer = new byte[blockSize];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        for (int i = 0; i < plaintext.length(); i += blockSize) {
            int length = Math.min(blockSize, plaintext.length() - i);
            byte[] encryptedBlock = cipher.doFinal(plaintext.substring(i, i + length).getBytes(StandardCharsets.UTF_8));
            outputStream.write(encryptedBlock);
        }

        return outputStream.toByteArray();
    }

    public static String decryptWithPrivateKey(byte[] ciphertext) throws Exception {
        // Create a cipher object using the private key and decryption algorithm
        Cipher cipher = Cipher.getInstance(node_rsa_init);
        PrivateKey privateKey = readPrivateKeyFromPem();

        cipher.init(Cipher.DECRYPT_MODE, privateKey,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));


        // Divide the ciphertext into smaller chunks of a fixed size
        int blockSize = 256;
        byte[] buffer = new byte[blockSize];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        for (int i = 0; i < ciphertext.length; i += blockSize) {
            int length = Math.min(blockSize, ciphertext.length - i);
            byte[] decryptedBlock = cipher.doFinal(ciphertext, i, length);
            outputStream.write(decryptedBlock);
        }

        // Convert the decrypted data to a string
        return new String(outputStream.toByteArray(), StandardCharsets.UTF_8);
    }

    public static PublicKey readPublicKeyFromPem() throws Exception {
        ClassLoader classLoader = CryptoHelper.class.getClassLoader();
        URL resourceUrl = classLoader.getResource("public_key.pem");
        Path filePath = Paths.get(resourceUrl.toURI());

        // Read the file content as an InputStream
        InputStream inputStream = Files.newInputStream(filePath);
        byte[] keyBytes = new byte[inputStream.available()];
        inputStream.read(keyBytes);

        String keyString = new String(keyBytes);
        String privKeyPEM = keyString.replace("-----BEGIN PUBLIC KEY-----", "");
        privKeyPEM = privKeyPEM.replace("-----END PUBLIC KEY-----", "");
        privKeyPEM = privKeyPEM.replace("\r", "");
        privKeyPEM = privKeyPEM.replace("\n", "");
        keyBytes = Base64.getDecoder().decode(privKeyPEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static PrivateKey readPrivateKeyFromPem() throws Exception {
        return readPrivateKeyFromPem_PKCS8();
    }

    public static PrivateKey readPrivateKeyFromPem_PKCS8() throws Exception {
        ClassLoader classLoader = CryptoHelper.class.getClassLoader();
        URL resourceUrl = classLoader.getResource("private_key.pem");
        Path filePath = Paths.get(resourceUrl.toURI());

        // Read the file content as an InputStream
        InputStream inputStream = Files.newInputStream(filePath);
        byte[] keyBytes = new byte[inputStream.available()];
        inputStream.read(keyBytes);


        String keyString = new String(keyBytes);
        String privKeyPEM = keyString.replace("-----BEGIN PRIVATE KEY-----", "");
        privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
        privKeyPEM = privKeyPEM.replace("\r", "");
        privKeyPEM = privKeyPEM.replace("\n", "");
        keyBytes = Base64.getDecoder().decode(privKeyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
}
