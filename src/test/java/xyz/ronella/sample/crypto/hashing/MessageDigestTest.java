package xyz.ronella.sample.crypto.hashing;

import org.junit.jupiter.api.Test;
import xyz.ronella.trivial.decorator.StringBuilderAppender;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MessageDigestTest {

    @Test
    public void testSHA256() throws NoSuchAlgorithmException {
        final var password = "password123";
        final var algorithm = "SHA-256";

        final var digest = MessageDigest.getInstance(algorithm);
        final var hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));

        // Convert the byte array into a hexadecimal string
        final var hexString = new StringBuilderAppender();

        for (final var b : hash) {
            final var hex = Integer.toHexString(0xff & b);
            hexString.append(()-> hex.length() == 1, "0").append(hex);
        }

        final var expectedHash = "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f";
        final var hashOutput = hexString.toString();

        assertEquals(expectedHash, hashOutput);

    }

}
