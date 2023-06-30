import javax.crypto.Cipher;
import java.security.SecureRandom;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.BadPaddingException;

/**
 * This class shows how to securely perform AES encryption in GCM mode, with 256
 * bits key size.
 */
public class Aes256GcmPkcs5Test {

    public static int IV_SIZE = 96;
    public static int TAG_BIT_LENGTH = 128;
    public static String ALGO_TRANSFORMATION_STRING = "AES/GCM/PKCS5Padding";
    byte[] aadData = "qne.cloud".getBytes();

    public static int AES_KEY_SIZE = 256;

    public static void main(String args[]) {
        String sessionKey = "EZe+RjDu+5+fiMrOULtJrkCtOwfL/tcymWFZ/zJ32W0=";
        String iv = "IQQjOqh1dHIUYAbVAQ3UqnjBaEqqutO%2ByzepCUsp9Ois%2B7EKFSbz2ykHkL6GCBYaw5cwfc6Mkh7fFgAEOBwC9OG8WwPEXpa3P2RrBeWqY%2BqAxUM7yiTtT3CvcK5VYXbx";
        String encryptedPayload = "l6BhkPQRot6BxKsjcRBU70139PGosvmHku0Sky3OchEEHqeDt+u/7Nkz3xZsnS4zHD1CcD6rbU0gr9Z/aR+j9D6egA/uFU2k9LU9tA9ySwKX2HdU8Rs4y4aoGJTUpt9WJPfyk50wbe2nuu9tPUpFhX6yvV0ice3oBHoUFPbQp827T1Vcc8EiTYj9kOA9uKw5EUZ2BwMhr0CEfFqJUTpZAy1WxKBUJAGwSWXMcN/QtYlPSh/ADOh6bzWLfVFunTRBcaKqknA62F4unqm/EC3wGAw9RtS1Z4nIpUipUDhAdHwPiFCRkyy5SkX8EzDhq9heNX2nb8auCv+/WaD1T4IE0zFU3LiMuxDIQtsqKIpLnlN0c/Ttg1jtXaOs+vFP29FDeOJS3HHT8AY+jELWvvanPLjelV1LO9GGH0bO7I/tiJE55TMMsqXKBKYCN6gbQqA/4gWFF3LoG/I2zULyNcDSvx0EyYooD7/APw6SgtWeer2rqPh6aKtXdonEKe+ENOniYs1djhFd+QHTYw6FJ/69+nmmNBTNYW8oKiKpVtAticEFza+38LFqzla8orFHRAZ/FeVg9eP7IIpyM8t5eflzRmvRV0BgV7zfmIGa7avkV9YB0jzbhk3Pi8F3E5bDYMGHhArnme4dcH678Gd5ZeHsmQlpkz7eh4IzEZIo6z9c9GPqx0KsPugU2WQIOSFqfgIatYud2Zw8PSVK8aFXKJOFfhOGdvK3LT0DkIaBq9t1ATTysTG8oqp7qEydCStsRquy3tAOySpQeBQfePnLA6P0cj3pUPVU";

        byte[] aadData = "qne.cloud".getBytes();

        byte[] decryptedText = aesDecrypt(Base64.getDecoder().decode(encryptedPayload), sessionKey, iv, aadData);

        System.out.println("Decrypted text " + new String(decryptedText));
    }

    public static byte[] aesDecrypt(byte[] encryptedMessage, String key, String iv,
            byte[] aadData) {
        Cipher c = null;

        try {
            c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING); // Transformation specifies algortihm, mode of operation
                                                                // and padding
        } catch (NoSuchAlgorithmException noSuchAlgoExc) {
            System.out.println("Exception while decrypting. Algorithm being requested is not available in environment "
                    + noSuchAlgoExc);
            System.exit(1);
        } catch (NoSuchPaddingException noSuchAlgoExc) {
            System.out.println(
                    "Exception while decrypting. Padding scheme being requested is not available in environment "
                            + noSuchAlgoExc);
            System.exit(1);
        }

        try {
            SecretKeySpec secret = new SecretKeySpec(key.getBytes(), "AES");

            // Initialize GCM Parameters
            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv.getBytes());
            c.init(Cipher.DECRYPT_MODE, secret, gcmParamSpec, new SecureRandom());
        } catch (InvalidKeyException invalidKeyExc) {
            System.out.println(
                    "Exception while encrypting. Key being used is not valid. It could be due to invalid encoding, wrong length or uninitialized "
                            + invalidKeyExc);
            System.exit(1);
        } catch (InvalidAlgorithmParameterException invalidParamSpecExc) {
            System.out.println(
                    "Exception while encrypting. Algorithm Param being used is not valid. " + invalidParamSpecExc);
            System.exit(1);
        }

        try {
            c.updateAAD(aadData); // Add AAD details before decrypting
        } catch (IllegalArgumentException illegalArgumentExc) {
            System.out.println("Exception thrown while encrypting. Byte array might be null " + illegalArgumentExc);
            System.exit(1);
        } catch (IllegalStateException illegalStateExc) {
            System.out.println("Exception thrown while encrypting. CIpher is in an illegal state " + illegalStateExc);
            System.exit(1);
        }

        byte[] plainTextInByteArr = null;
        try {
            plainTextInByteArr = c.doFinal(encryptedMessage);
        } catch (IllegalBlockSizeException illegalBlockSizeExc) {
            System.out.println("Exception while decryption, due to block size " + illegalBlockSizeExc);
            System.exit(1);
        } catch (BadPaddingException badPaddingExc) {
            System.out.println("Exception while decryption, due to padding scheme " + badPaddingExc);
            System.exit(1);
        }

        return plainTextInByteArr;
    }
}