import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import org.apache.commons.codec.binary.Hex;

/**
 * DOC chuang class global comment. Detailled comment
 */
public class App {
    public static String ENCRYPT_KEY = "Encrypt"; //$NON-NLS-1$
    private static String rawKey = "Talend-Key"; //$NON-NLS-1$
    private static SecretKey key = null;
    private static SecureRandom secureRandom = new SecureRandom();
    private static String CHARSET = "UTF-8";

    private static SecretKey getSecretKey() throws Exception {
        if (key == null) {
            byte rawKeyData[] = rawKey.getBytes(CHARSET);

            DESKeySpec dks = new DESKeySpec(rawKeyData);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES"); //$NON-NLS-1$
            key = keyFactory.generateSecret(dks);
        }
        return key;
    }

    private static SecretKey getSecretKey(String inputKey) throws Exception {
        if (key == null) {
            byte rawKeyData[] = inputKey.getBytes(CHARSET);
            DESKeySpec dks = new DESKeySpec(rawKeyData);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES"); //$NON-NLS-1$
            key = keyFactory.generateSecret(dks);
        }
        return key;
    }

    public static String encryptPassword(String input) throws Exception {
        if (input == null) {
            return input;
        }
        SecretKey key = getSecretKey();
        Cipher c = Cipher.getInstance("DES"); //$NON-NLS-1$
        c.init(Cipher.ENCRYPT_MODE, key, secureRandom);
        byte[] cipherByte = c.doFinal(input.getBytes(CHARSET));
        String dec = Hex.encodeHexString(cipherByte);
        return dec;
    }

    public static String encryptPassword(String input, String inputKey) throws Exception {
        if (input == null) {
            return input;
        }
        SecretKey key = getSecretKey(inputKey);
        Cipher c = Cipher.getInstance("DES"); //$NON-NLS-1$
        c.init(Cipher.ENCRYPT_MODE, key, secureRandom);
        byte[] cipherByte = c.doFinal(input.getBytes(CHARSET));
        String dec = Hex.encodeHexString(cipherByte);
        return dec;
    }

    public static String decryptPassword(String input) {
        if (input == null || input.length() == 0) {
            return input;

        }
        try {
            byte[] dec = Hex.decodeHex(input.toCharArray());
            SecretKey key = getSecretKey();
            Cipher c = Cipher.getInstance("DES"); //$NON-NLS-1$
            c.init(Cipher.DECRYPT_MODE, key, secureRandom);
            byte[] clearByte = c.doFinal(dec);
            return new String(clearByte, CHARSET);
        } catch (Exception e) {
            // do nothing
        }
        return input;
    }

    public static String decryptPassword(String input, String keyInput) {
        if (input == null || input.length() == 0) {
            return input;
        }
        try {
            byte[] dec = Hex.decodeHex(input.toCharArray());
            SecretKey key = getSecretKey(keyInput);
            Cipher c = Cipher.getInstance("DES"); //$NON-NLS-1$
            c.init(Cipher.DECRYPT_MODE, key, secureRandom);
            byte[] clearByte = c.doFinal(dec);
            return new String(clearByte, CHARSET);
        } catch (Exception e) {
            // do nothing
            e.printStackTrace();
        }
        return input;
    }

    public static void main(String[] args) {
        try {
            System.out.println(encryptPassword("1234", "AB$L!@2021"));
            System.out.println(decryptPassword("c79ab61458e32fe0", "AB$L!@2021"));
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
        }
    }
}