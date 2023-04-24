# Sample Crypto Implementations

This project contains only the test of the basic implementations of different cryptographic algorithms.

**Hashing algorithms are used to generate a fixed-size output, called a hash or message digest, from input data of any size.** They are commonly used to verify the integrity of data by comparing the hash of the original data to the hash of the received data.

The sample implementation is available in the following test file:

```
xyz.ronella.sample.crypto.hashing.MessageDigestTest
```

**Symmetric algorithms use a single key to both encrypt and decrypt data.** The same key must be used by both parties to communicate securely.

The sample implementations are available in the following test files:

```
xyz.ronella.sample.crypto.symmetric.AESECBPKCS5PaddingTest
```

> ECB mode is suitable for encrypting small amounts of data that do not have any patterns. This means that identical plaintext blocks will be encrypted into identical ciphertext blocks.

```
xyz.ronella.sample.crypto.symmetric.AESCBCPKCS5PaddingTest
```

> In CBC mode, each plaintext block is XORed with the previous ciphertext block before encryption. This means that identical plaintext blocks will not result in identical ciphertext blocks.

**Asymmetric algorithms use a pair of keys, a public key and a private key, to encrypt and decrypt data.** The public key can be freely distributed while the private key must be kept secret. Asymmetric algorithms are commonly used for key exchange, digital signatures, and secure communication.

The sample implementation is available in the following test file:

```
xyz.ronella.sample.crypto.asymmetric.RSA2048Test
```

