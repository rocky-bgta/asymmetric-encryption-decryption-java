import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.InputStream;
import java.net.URL;
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

/**
 * Cryptography helper
 */
public class CryptoHelper {
    private static String node_rsa_init = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static void main(String[] args) {

        try {
            // Key file names
            // String pubkeyfile = "../pbkey.pem";
            //String privateKeyfile = "../pvkey.pem";
            // https://acte.ltd/utils/openssl

            /*

            # Private key
                        openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

            # Public key
                        openssl rsa -pubout -in private.pem -out public_key.pem

            # Private key in pkcs8 format (for Java maybe :D)
                        openssl pkcs8 -topk8 -in private.pem -out private_key.pem

            ## nocrypt (Private key does have no password)
                        openssl pkcs8 -topk8 -in private.pem -nocrypt -out private_key.pem
            */


            // encrypt
            String s = "The quick brown fox jumps over the lazy dog";
            String enc = CryptoHelper.encryptStringWithPublicKey(s);
            System.out.println( String.format("%s -> %s", s, enc));


            String dec = CryptoHelper.decryptStringWithPrivateKey(enc);
            //System.out.println(String.format("%s -> %s", enc, dec));
        } catch (Exception ex) {
            System.out.println(ex);
        }

    }

    public static String encryptStringWithPublicKey(String s) throws Exception {
        Cipher cipher = Cipher.getInstance(node_rsa_init);
        PublicKey pubkey = readPublicKeyFromPem();
        // encrypt
        // cipher init compatible with node.js crypto module!
        cipher.init(Cipher.ENCRYPT_MODE, pubkey,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        String enc = Base64.getEncoder().encodeToString(cipher.doFinal(s.getBytes("UTF-8")));
        return enc;
    }

    public static String decryptStringWithPrivateKey(String s) throws Exception {
        Cipher cipher = Cipher.getInstance(node_rsa_init);
        PrivateKey pkey = readPrivateKeyFromPem();
        // cipher init compatible with node.js crypto module!
        cipher.init(Cipher.DECRYPT_MODE, pkey,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        String dec = new String(cipher.doFinal(Base64.getDecoder().decode(s)), "UTF-8");

        return dec;
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

}