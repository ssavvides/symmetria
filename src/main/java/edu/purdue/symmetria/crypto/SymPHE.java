package edu.purdue.symmetria.crypto;


import edu.purdue.symmetria.crypto.cipher.RangeSymCipher;
import edu.purdue.symmetria.crypto.cipher.SymCipher;
import edu.purdue.symmetria.crypto.cipher.SymCipher.CipherType;
import edu.purdue.symmetria.utils.ByteUtils;
import edu.purdue.symmetria.utils.MathUtils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public abstract class SymPHE extends CryptoScheme {

    static final CipherType DEFAULT_CIPHER_TYPE = CipherType.RANGE;

    // arithmetic modulo
    public long modulo;

    public BigInteger moduloBI; // modulo as a BI

    // threshold that separates positive from negative numbers
    public long negThreshold;

    // what type of cipher to use. This includes the method to use to handle id lists.
    CipherType cipherType;

    // the next id to use
    long nextId;

    // used to generate random numbers
    Cipher aesBlockCipher;

    public SymPHE(CipherType cipherType, int negDivisor, String privateKeyPath) {
        super(privateKeyPath);
        this.cipherType = cipherType;
        setupRandNum();
        nextId = 1;
    }

    /**
     * Returns a cipher of the given type.
     */
    static SymCipher generateCipher(CipherType cipherType, long value, long id) {
        SymCipher cipher;
        if (cipherType == CipherType.RANGE)
            cipher = new RangeSymCipher(value, id);
        else
            throw new RuntimeException("Invalid cipher type");
        return cipher;
    }

    /**
     * Encrypt the given message
     */
    public abstract SymCipher encrypt(long message);

    /**
     * Decrypt the given ciphertext.
     */
    public abstract long decrypt(SymCipher ciphertext);


    /**
     * Returns the next id to use to encrypt.
     */
    public long getNextId() {
        return nextId++;
    }

    /**
     * Returns a positive long number in the range 0-n. The number is generated using a keyed random
     * number generator.
     */
    public long getRandNum(long id, long modulo) {
        byte[] b = new byte[0];
        try {
            b = aesBlockCipher.doFinal(String.valueOf(id).getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return MathUtils.mod(ByteUtils.bytesToLong(b), modulo);
    }


    /**
     * Setup cipher used for generating random numbers
     */
    void setupRandNum() {
        String algorithm = "AES";
        String key = (String) privateKey;
        try {
            byte[] keyBA = key.getBytes(StandardCharsets.UTF_8);
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            keyBA = sha.digest(keyBA);
            keyBA = Arrays.copyOf(keyBA, 16);

            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBA, algorithm);
            aesBlockCipher = Cipher.getInstance(algorithm);
            aesBlockCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    /**
     * Setup the threshold between positive and negative numbers.
     */
    void setupNegative(int negDivisor) {
        negThreshold = 0;
        if (negDivisor != 1)
            negThreshold = modulo / negDivisor;
    }

    /**
     * Shift the given message to allow representing negative numbers.
     */
    public long handleNegative(long m) {
        if (negThreshold != 0 && m >= negThreshold)
            m = m - modulo;
        return m;
    }
}
