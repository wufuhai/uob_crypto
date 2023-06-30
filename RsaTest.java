import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;
import java.lang.Exception;
import java.security.Key;
import java.security.KeyPair;

public class RsaTest {

    static String ALGORITHM_NAME = "RSA";
    static String PADDING_SCHEME = "PKCS1Padding";
    // This essentially means none behind the scene
    static String MODE_OF_OPERATION = "ECB";
    static int RSA_KEY_LENGTH = 4096;

    public static void main(String[] args) {
        String shortMessage = "abc123";
        try {
            // Generate Key Pairs
            //KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(ALGORITHM_NAME);
            //rsaKeyGen.initialize(RSA_KEY_LENGTH);
            //KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();

            JwtKeyReader.ReadAliases();
            Key pubKey = JwtKeyReader.getPublicKey();
            String encryptedText = RsaCrypto.rsaEncrypt(shortMessage, pubKey);

            Key privKey = JwtKeyReader.getPrivateKey();
            String decryptedText = RsaCrypto.rsaDecrypt(Base64.getDecoder().decode(encryptedText), privKey);

            System.out.println("Encrypted text = " + encryptedText);
            System.out.println("Decrypted text = " + decryptedText);

        } catch (Exception e) {
            System.out.println("Exception while encryption/decryption");
            e.printStackTrace();
        }
    }

    class RsaCrypto {
        public static String rsaEncrypt(String message, Key publicKey) throws Exception {

            Cipher c = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME);

            c.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] cipherTextArray = c.doFinal(message.getBytes());

            return Base64.getEncoder().encodeToString(cipherTextArray);

        }

        public static String rsaDecrypt(byte[] encryptedMessage, Key privateKey) throws Exception {
            Cipher c = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME);
            c.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] plainText = c.doFinal(encryptedMessage);

            return new String(plainText);

        }
    }
}
