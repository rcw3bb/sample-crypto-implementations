package xyz.ronella.sample.crypto.symmetric;

import org.junit.jupiter.api.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AESCBCPKCS5PaddingTest {

    private static String KEY;

    //The initialization vector (IV) must be 16 bytes (128 bits) in length.
    // This is because AES is a block cipher that operates on 128-bit blocks,
    // and the IV is used to initialize the first block of plaintext before it is encrypted.
    private static String INITIALIZATION_VECTOR;
    private static final String PLAIN_TEXT = "THIS IS A SECRET";
    private static String CIPHER_TEXT;

    @BeforeAll
    public static void initialize() {
        //The symmetric key to use for encryption and decryption.
        KEY = generateKey();
        INITIALIZATION_VECTOR = "0123456789abcdef";
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

    private static byte[] decodeKey(final String encodedKey) {
        return Base64.getDecoder().decode(encodedKey);
    }

    @Test
    @Order(10)
    public void testAES256Encrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        final var keyBytes = decodeKey(KEY);
        final var ivBytes = INITIALIZATION_VECTOR.getBytes();

        final var key = new SecretKeySpec(keyBytes, "AES");
        final var iv = new IvParameterSpec(ivBytes);

        final var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        final var plaintextBytes = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);
        final var ciphertextBytes = cipher.doFinal(plaintextBytes);
        CIPHER_TEXT = Base64.getEncoder().encodeToString(ciphertextBytes);

        System.out.printf("Cipher %s%n", CIPHER_TEXT);
        assertFalse(CIPHER_TEXT.isEmpty());
    }

    @Test
    @Order(20)
    public void testAES256Decrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        final var keyBytes = decodeKey(KEY);
        final var ivBytes = INITIALIZATION_VECTOR.getBytes();

        final var key = new SecretKeySpec(keyBytes, "AES");
        final var iv = new IvParameterSpec(ivBytes);

        final var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        final var decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(CIPHER_TEXT));
        final var decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

        System.out.printf("Secret %s%n", decryptedText);

        assertEquals(PLAIN_TEXT, decryptedText);
    }

}
