package xyz.ronella.sample.crypto.asymmetric;

import org.junit.jupiter.api.*;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class RSA2048Test {

    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;
    private static String PRIVATE_KEY;
    private static String PUBLIC_KEY;
    private static final String PLAIN_TEXT = "THIS IS A SECRET";
    private static String CIPHER_TEXT;

    @BeforeAll
    public static void init() throws NoSuchAlgorithmException {
        final var keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        final var keyPair = keyPairGenerator.generateKeyPair();
        final var publicKey = keyPair.getPublic();
        final var privateKey = keyPair.getPrivate();

        PRIVATE_KEY = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        PUBLIC_KEY = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        // Store the keys as strings
        System.out.printf("Private Key: %s%nPublic Key: %s%n", PRIVATE_KEY, PUBLIC_KEY);
    }

    private static PrivateKey getPrivateKeyFromString(String keyString) throws Exception {
        final var keyBytes = Base64.getDecoder().decode(keyString);
        final var spec = new PKCS8EncodedKeySpec(keyBytes);
        final var kf = KeyFactory.getInstance(ALGORITHM);
        return kf.generatePrivate(spec);
    }

    private static PublicKey getPublicKeyFromString(String keyString) throws Exception {
        final var keyBytes = Base64.getDecoder().decode(keyString);
        final var spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        return kf.generatePublic(spec);
    }

    @Test
    @Order(10)
    public void testEncryptByPublicKey() throws Exception {
        final var cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKeyFromString(PUBLIC_KEY));

        final var plaintextBytes = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);
        final var ciphertextBytes = cipher.doFinal(plaintextBytes);

        CIPHER_TEXT = Base64.getEncoder().encodeToString(ciphertextBytes);

        System.out.printf("Cipher %s%n", CIPHER_TEXT);
        assertFalse(CIPHER_TEXT.isEmpty());
    }

    @Test
    @Order(20)
    public void testDecryptByPrivateKey() throws Exception {
        final var decryptCipher = Cipher.getInstance(ALGORITHM);
        decryptCipher.init(Cipher.DECRYPT_MODE, getPrivateKeyFromString(PRIVATE_KEY));

        final var decryptedBytes = decryptCipher.doFinal(Base64.getDecoder().decode(CIPHER_TEXT));
        final var decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

        System.out.printf("Secret %s%n", decryptedText);

        assertEquals(PLAIN_TEXT, decryptedText);
    }
}
