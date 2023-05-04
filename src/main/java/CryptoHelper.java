import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoHelper {
    private static String node_rsa_init = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private final static int blockSize = 190;
    public static void main(String[] args) throws Exception {

        // Encrypt a long string in small chunks using the public key
        String longString = "{\"statusType\":\"OK\",\"entity\":[{\"customerStatusId\":2,\"customerStatusName\":\"Data Received\",\"customerStatusDescription\":\"Data Received\"},{\"customerStatusId\":3,\"customerStatusName\":\"Data Verification In Progress\",\"customerStatusDescription\":\"Data Verification In Progress\"},{\"customerStatusId\":5,\"customerStatusName\":\"Data Verification Failed\",\"customerStatusDescription\":\"Data Verification Failed\"},{\"customerStatusId\":7,\"customerStatusName\":\"Credit Approved\",\"customerStatusDescription\":\"Credit Approved\"},{\"customerStatusId\":16,\"customerStatusName\":\"Temporary Block\",\"customerStatusDescription\":\"Temporary Block\"},{\"customerStatusId\":11,\"customerStatusName\":\"Permanent Block\",\"customerStatusDescription\":\"Permanent Block\"}],\"entityType\":\"java.util.ArrayList\",\"metadata\":{},\"status\":200}";
        String encryptedString  = encryptWithPublicKey(longString);

        // Print the encrypted string in Base64 format
        System.out.println("Encrypted string:");
        System.out.println(encryptedString);

        String encryptionFromJavaScript = "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";

        // Decrypt the encrypted string using the private key
        String decryptedString = decryptWithPrivateKey(encryptedString);

        System.out.println("Decrypted string:");
        System.out.println(decryptedString);
    }

    public static String encryptWithPublicKey(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(node_rsa_init);
        PublicKey publicKey = readPublicKeyFromPem();

        cipher.init(Cipher.ENCRYPT_MODE, publicKey,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));

        // Divide the plaintext into smaller chunks of a fixed size
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (int i = 0; i < plaintext.length(); i += blockSize) {
            int length = Math.min(blockSize, plaintext.length() - i);
            byte[] encryptedBlock = cipher.doFinal(plaintext.substring(i, i + length).getBytes(StandardCharsets.UTF_8));
            outputStream.write(encryptedBlock);
        }

        byte[] encrypted = outputStream.toByteArray();
        return Base64.getEncoder().encodeToString(encrypted);
    }


    public static String decryptWithPrivateKey(String base64Ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(node_rsa_init);
        PrivateKey privateKey = readPrivateKeyFromPem();

        cipher.init(Cipher.DECRYPT_MODE, privateKey,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));

        // Decode the Base64-encoded ciphertext
        byte[] ciphertext = Base64.getDecoder().decode(base64Ciphertext);

        // Divide the ciphertext into smaller chunks of a fixed size
        int blockSize = 256;
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
        ClassLoader classLoader = CryptoHelperOld.class.getClassLoader();
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
        ClassLoader classLoader = CryptoHelperOld.class.getClassLoader();
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
