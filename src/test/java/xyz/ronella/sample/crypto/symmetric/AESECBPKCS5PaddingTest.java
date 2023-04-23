package xyz.ronella.sample.crypto.symmetric;

import org.junit.jupiter.api.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AESECBPKCS5PaddingTest {

    private static String KEY;
    private static final String PLAIN_TEXT = "THIS IS A SECRET";
    private static String CIPHER_TEXT;

    @BeforeAll
    public static void initialize() {
        //The symmetric key to use for encryption and decryption.
        KEY = generateKey();
    }

    private static String generateKey() {
        try {
            final var keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            final var secretKey = keyGenerator.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static SecretKey decodeKey(final String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    @Test
    @Order(10)
    public void testAES256Encrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final var secret = decodeKey(KEY);

        final var cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);

        final var plaintextBytes = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);
        final var ciphertextBytes = cipher.doFinal(plaintextBytes);
        CIPHER_TEXT = Base64.getEncoder().encodeToString(ciphertextBytes);

        System.out.printf("Cipher %s%n", CIPHER_TEXT);

        assertFalse(CIPHER_TEXT.isEmpty());
    }

    @Test
    @Order(20)
    public void testAES256Decrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final var secretKey = decodeKey(KEY);

        final var cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        final var decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(CIPHER_TEXT));
        final var decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

        System.out.printf("Secret %s%n", decryptedText);
        assertEquals(PLAIN_TEXT, decryptedText);
    }

}
