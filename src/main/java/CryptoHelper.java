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
    // https://mkyong.com/java/java-asymmetric-cryptography-example/
    // https://stackoverflow.com/questions/44681737/get-a-privatekey-from-a-rsa-pem-file

    private static String node_rsa_init = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
  
    public static void main(String[] args){
  
        try {
            // Key file names
            // String pubkeyfile = "../pbkey.pem";
            //String privateKeyfile = "../pvkey.pem";
            // https://acte.ltd/utils/openssl

/*  # Private key
            openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

# Public key
            openssl rsa -pubout -in private.pem -out public_key.pem

# Private key in pkcs8 format (for Java maybe :D)
            openssl pkcs8 -topk8 -in private.pem -out private_key.pem

## nocrypt (Private key does have no password)
            openssl pkcs8 -topk8 -in private.pem -nocrypt -out private_key.pem
*/

            String pubkeyfile =
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArUqb0FiaIv/sEnTo1J8z" +
                    "rAA2nBJt3oRqI83kJcrZ7hwVYy0mI+QG+wxFmMUah8dZ1sIB6G5R+6zG4vJpXyYF" +
                    "pw2lWcWAKZzu6uKub8KxFHMbrCLyoH5sxZlEz+YThZK6u04EHHLnq7q5UKbmyL/H" +
                    "y08IlJzuTUfEf8XUrIXSRub6hCUYIQnbxK2EiYwApFwd0dAsxzegEcdnA7sg2066" +
                    "50VphL2btRqJ57g2zcta6bQNjo+G6MUrvXbGtvb3s1F6tynxufj+sqig3UrDTgBV" +
                    "AkunPKHWSndR8fTzajF29QNXXJMQYrDmbSu3GR5Tk64uBrIuHo8vHFeCxFr5rlJQ" +
                    "DwIDAQAB";



            String privateKeyfile =
                    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCtSpvQWJoi/+wS" +
                    "dOjUnzOsADacEm3ehGojzeQlytnuHBVjLSYj5Ab7DEWYxRqHx1nWwgHoblH7rMbi" +
                    "8mlfJgWnDaVZxYApnO7q4q5vwrEUcxusIvKgfmzFmUTP5hOFkrq7TgQccuerurlQ" +
                    "pubIv8fLTwiUnO5NR8R/xdSshdJG5vqEJRghCdvErYSJjACkXB3R0CzHN6ARx2cD" +
                    "uyDbTrrnRWmEvZu1GonnuDbNy1rptA2Oj4boxSu9dsa29vezUXq3KfG5+P6yqKDd" +
                    "SsNOAFUCS6c8odZKd1Hx9PNqMXb1A1dckxBisOZtK7cZHlOTri4Gsi4ejy8cV4LE" +
                    "WvmuUlAPAgMBAAECggEAKZMLvLl1CU6S6X6o2VH0iKBoeZsmRstH150uzi5TiH+u" +
                    "VePgEZ5EWniAPf2Ttt2J3S8gXA4TlyjFcm8r/orVslVgxR/P9qvS2gFWTjPMXhab" +
                    "nfmocf7Cw8lYq/QL3PDt4b/+1oBuulGK4iGYnrL8EPe+HEFmHp5IM0tYEaftYdrl" +
                    "MHeFix7JTUZmiIubS50hdfnMdsNFkKoUjRJADlrFmcLP3+XFAY0fa8VZ3gQryIUN" +
                    "mKB10pQDdUPqrFeIgkADG2aHLi9eahtX4nNUutNAskk52LRbeCEUVtu2CfpALXA5" +
                    "3w6cp4D+RVNAb6EuZZu7AO5V1qvoByODSd0araHlwQKBgQDdd0GuazTdb6s5pYH0" +
                    "6OJkv8DWyf9rtyqy6UZawE0RK47c+85mZNtTsQlmyXOuBT9Z/R+fbjNgcHY/J7ad" +
                    "JRvXeCs3Cr+zuJ3EV2jaGnmZ3dRxXX4TA2ctjWJc7Md1bgotwTgb/bmATD4bkbOI" +
                    "DRyUbM0jGxTkCcCYOQlBQ2CkYQKBgQDIUER4E6SQdgA6VT6wD88FwaffqNnk/0Kg" +
                    "7+YHTfi5mXMEhVNcE00/SMrCFwiQodEZZnO5H6d2+O7ALwnUAW2LOTy4nxAwCevU" +
                    "CyE+mOGbpP7/yMwyLozFtvlxMXRTfssQQFkWQkJZHT1s2cseQd+Ytg6MngNgE1Rl" +
                    "0xErkUdKbwKBgHbOwWemj6ezfnHgfkU6oilWTUds+h95FekBCAMrYqyxZ2TZmTKJ" +
                    "LLhLIzYHII3cts254zsOTXWRH35l+at3+uWuy9AtbgYmJkzsb42B4nZO8OcYNshQ" +
                    "bQuc64XaaG5w5/j/zPAHP3q6bB8yHNQB5LEjZTFOF/j12mJPRs3CLZhBAoGBAK/F" +
                    "348OjYVGRoTpcIzGEn+Wo1ybqjhL1Yere0pFnVAf2tHIvJE7TrmNgn42AAoKNJX5" +
                    "VOrJYAYCAl8Z56Hlbt6QZzwKOAYvboUvDwkC1lXhvvFsneIa/uQv30r4fn8V79Je" +
                    "5M2nbtkL027E3nu6ih5TAwlZTtTroU+ImrSEUu55AoGAb9/WeQV2C5JiA93WIcFg" +
                    "JtFDO1cYNFpYvVqpAuRnfBes2VBxCxVfP5CdroNzYdj5qroyMsZDoCGsiMwkIp2i" +
                    "CRwSBh8kNj7sut8Gd9Xw3oe5o9VTrZRbQeKfDZBlVwLXjjwF2AaHZi7ChllmwNUV" +
                    "Q+xK7RaJrgbd9uIqQR6Ehoo=";







  
            // encrypt
        String s = "The quick brown fox jumps over the lazy dog"; 
            String enc = CryptoHelper.encryptStringWithPublicKey(s);
            //System.out.println( String.format("%s -> %s", s, enc));
  
            // decrypt
            String nodeJSEncrypted="O9UhqjomngHWkLzSsyMurY96KLgDWTxxqc37KLrQoUryTy1c6smpRnVKAfikEPNCpUpAjTaHtUseR+9Mk/O5HvlIfovn1vuwyBq7u6DMf2NWKjZswvU14N+Cp3E2OMVb5biWJZRQs9htG7/A7oW2pxW3DGZxF0yftxJZNryICQmydj73+kq0anG15pyNwnyID2uu4/tngyABxOfSf+f5Yf/yDeKXEMDlcxMfnCxjnKhn1C+uufxG0PGGgYev9lYNQBPkZMQ0Lfhm/VGDulfUTJ6VNYnCxqM6t1t4ixJyjrBglTJdStMwP+FuVBf9w3LKd9G3gzNvTgyg+RV2S9h8+A==";

            String dec = CryptoHelper.decryptStringWithPrivateKey(nodeJSEncrypted);
            System.out.println( String.format("%s -> %s", enc, dec));
        }
        catch(Exception ex){
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
  
    public static String decryptStringWithPrivateKey(String s)  throws Exception {
        Cipher cipher = Cipher.getInstance(node_rsa_init);
        PrivateKey pkey = readPrivateKeyFromPem();
        // cipher init compatible with node.js crypto module!
        cipher.init(Cipher.DECRYPT_MODE, pkey,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        String dec = new String(cipher.doFinal(Base64.getDecoder().decode(s)), "UTF-8");
 
        return dec;
    }
  
    public static PrivateKey readPrivateKeyFromPem() throws Exception {
        //byte[] keyBytes = Base64.getDecoder().decode(keyFilename);
        //String keyString = new String(keyBytes);
  
        //if (keyString.contains("BEGIN PRIVATE KEY")) {
            // PCKS8 format key
       //     return readPrivateKeyFromPem_PKCS8(keyFilename);
       // }
       // else if(keyString.contains("BEGIN RSA PRIVATE KEY")){
            // PCKS1 format key
            return readPrivateKeyFromPem_PKCS8();
       // }
        // unknown format
       // throw new Exception("Unknown private key format in "+keyFilename);
    }
  
    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
    public static PrivateKey readPrivateKeyFromPem_PKCS8() throws Exception {
        //byte[] keyBytes = Base64.getDecoder().decode(keyFilename);
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
  
    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
    public static PublicKey readPublicKeyFromPem() throws Exception {
        ClassLoader classLoader = CryptoHelper.class.getClassLoader();
        URL resourceUrl = classLoader.getResource("public_key.pem");
        Path filePath = Paths.get(resourceUrl.toURI());

        // Read the file content as an InputStream
        InputStream inputStream = Files.newInputStream(filePath);
        byte[] keyBytes = new byte[inputStream.available()];
        inputStream.read(keyBytes);

        //byte[] keyBytes = Base64.getDecoder().decode(keyFilename); //Files.readAllBytes(new File(keyFilename).toPath());
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
  
    // https://stackoverflow.com/questions/7216969/getting-rsa-private-key-from-pem-base64-encoded-private-key-file/55339208#55339208
    // https://github.com/Mastercard/client-encryption-java/blob/master/src/main/java/com/mastercard/developer/utils/EncryptionUtils.java
    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
    public static PrivateKey readPrivateKeyFromPem_PKCS1(String keyFilename) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyFilename); //Files.readAllBytes(new File(keyFilename).toPath());
        //String keyString = new String(keyBytes);
        //String privKeyPEM = keyString.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        //privKeyPEM = privKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");
        //privKeyPEM = privKeyPEM.replace("\r", "");
        //privKeyPEM = privKeyPEM.replace("\n", "");
  
        //keyBytes = Base64.getDecoder().decode(privKeyPEM);
  
        // We can't use Java internal APIs to parse ASN.1 structures, so we build a PKCS#8 key Java can understand
        int pkcs1Length = keyBytes.length;
        int totalLength = pkcs1Length + 22;
        byte[] pkcs8Header = new byte[] {
                0x30, (byte) 0x82, (byte) ((totalLength >> 8) & 0xff), (byte) (totalLength & 0xff), // Sequence + total length
                0x2, 0x1, 0x0, // Integer (0)
                0x30, 0xD, 0x6, 0x9, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0xD, 0x1, 0x1, 0x1, 0x5, 0x0, // Sequence: 1.2.840.113549.1.1.1, NULL
                0x4, (byte) 0x82, (byte) ((pkcs1Length >> 8) & 0xff), (byte) (pkcs1Length & 0xff) // Octet string + length
        };
        keyBytes = join(pkcs8Header, keyBytes);
  
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
  
    private static byte[] join(byte[] byteArray1, byte[] byteArray2){
        byte[] bytes = new byte[byteArray1.length + byteArray2.length];
        System.arraycopy(byteArray1, 0, bytes, 0, byteArray1.length);
        System.arraycopy(byteArray2, 0, bytes, byteArray1.length, byteArray2.length);
        return bytes;
   }
}