import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;

public class JwtKeyReader {
    public static PublicKey getPublicKey() throws Exception {
        Path path = Paths.get("uat/jwt/ioxgz.pem");
        BufferedReader reader = new BufferedReader(new FileReader(path.toFile()));
        StringBuilder builder = new StringBuilder();
        String line = null;
        while ((line = reader.readLine()) != null) {
            if (!line.startsWith("-----")) {
                builder.append(line);
            }
        }
        reader.close();
        byte[] keyBytes = Base64.getDecoder().decode(builder.toString());
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
        return publicKey;
    }

    public static void ReadAliases() throws Exception {
        // Load the keystore
        String password = "9679950";
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("uat/ssl/ssl.pfx"), password.toCharArray());

        // Get the aliases in the keystore
        Enumeration<String> aliases = keystore.aliases();

        System.out.println("SSL KeyStore Aliases");
        // Print out the elements
        while (aliases.hasMoreElements()) {
            String element = aliases.nextElement();
            System.out.println(element);
        }
    }

    public static PrivateKey getPrivateKey() throws Exception {

        FileInputStream keyFile = new FileInputStream("uat/jwt/ioxgz.key");
        byte[] keyBytes = new byte[keyFile.available()];
        keyFile.read(keyBytes);
        keyFile.close();
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        return privateKey;
        // Path path = Paths.get("uat/jwt/private.txt");
        // byte[] privateKeyBytes = Files.readAllBytes(path);
        // PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        // KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // PrivateKey privateKey = keyFactory.generatePrivate(privKeySpec);
        // return privateKey;
    }
}
