package edu.purdue.symmetria.crypto;

import edu.purdue.symmetria.crypto.cipher.ElGamalCipher;
import edu.purdue.symmetria.utils.ByteUtils;
import edu.purdue.symmetria.utils.FileUtils;

import java.io.Serializable;
import java.math.BigInteger;

public class ElGamal extends AsymPHE<ElGamalCipher> {

    private static final String DEFAULT_PUBLIC_KEY_PATH = "/tmp/elgamal.pk";
    private static final String DEFAULT_PRIVATE_KEY_PATH = "/tmp/elgamal.sk";

    private BigInteger g;
    private BigInteger h;
    private BigInteger x; // private key

    // precomputation
    private BigInteger preC1;
    private BigInteger preS;

    public ElGamal() {
        this(DEFAULT_NEGDIVISOR, DEFAULT_PUBLIC_KEY_PATH, DEFAULT_PRIVATE_KEY_PATH);
    }

    public ElGamal(int negDivisor, String publicKeyPath, String privateKeyPath) {
        super(publicKeyPath, privateKeyPath);

        // load keys
        ElGamalPK pk = (ElGamalPK) publicKey;
        n = pk.n;
        g = pk.g;
        h = pk.h;
        x = (BigInteger) privateKey;

        if (!ENABLE_RANDOM) {
            BigInteger r = new BigInteger(BITLENGTH, RNG);
            preC1 = g.modPow(r, n);
            preS = h.modPow(r, n);
        }

        setupNegative(negDivisor);
    }

    @Override
    public void keyGen() {
        BigInteger n = BigInteger.probablePrime(BITLENGTH, RNG);
        BigInteger g = BigInteger.probablePrime(BITLENGTH, RNG);
        BigInteger x;
        do {
            x = BigInteger.probablePrime(BITLENGTH, RNG);
        } while (!x.gcd(n).equals(BigInteger.ONE));
        BigInteger h = g.modPow(x, n);

        FileUtils.saveObjectToFile(x, privateKeyPath);
        FileUtils.saveObjectToFile(new ElGamalPK(n, g, h), publicKeyPath);
    }

    @Override
    public ElGamalCipher encrypt(long m) {
        BigInteger c1 = preC1;
        BigInteger s = preS;
        if (ENABLE_RANDOM) {
            BigInteger r = new BigInteger(BITLENGTH, RNG);
            c1 = g.modPow(r, n);
            s = h.modPow(r, n);
        }
        BigInteger c2 = BigInteger.valueOf(m).multiply(s).mod(n);
        return new ElGamalCipher(c1, c2);
    }

    @Override
    public long decrypt(ElGamalCipher c) {
        BigInteger m = c.c2.multiply(c.c1.modPow(x, n).modInverse(n)).mod(n);
        return handleNegative(m).longValue();
    }

    public ElGamalCipher multiply(ElGamalCipher c1, ElGamalCipher c2) {
        return new ElGamalCipher(c1.c1.multiply(c2.c1).mod(n), c1.c2.multiply(c2.c2).mod(n));
    }

    public ElGamalCipher multiplyPlaintext(ElGamalCipher c, long m) {
        return new ElGamalCipher(c.c1, c.c2.multiply(BigInteger.valueOf(m)).mod(n));
    }

    public ElGamalCipher divide(ElGamalCipher c1, ElGamalCipher c2) {
        ElGamalCipher res;
        try {
            res = this.multiply(c1, this.inverse(c2));
        } catch (Exception e) {
            return c1;
        }
        return res;
    }

    public ElGamalCipher pow(ElGamalCipher c, long m) {
        ElGamalCipher res;
        try {
            res = new ElGamalCipher(c.c1.modPow(BigInteger.valueOf(m), n), c.c2.modPow(BigInteger.valueOf(m), n));
        } catch (Exception e) {
            return c;
        }
        return res;
    }

    public ElGamalCipher inverse(ElGamalCipher c) {
        return pow(c, -1l);
    }

    @Override
    public String toString() {
        return "<ElGamal modLength=" + BITLENGTH + ">";
    }

    public static byte[] toBytes(ElGamalCipher c) {
        return ByteUtils.serialize(c);
    }

    public static ElGamalCipher fromBytes(byte[] bytes) {
        return (ElGamalCipher) ByteUtils.deserialize(bytes);
    }

}

class ElGamalPK implements Serializable {

    final BigInteger n;
    final BigInteger g;
    final BigInteger h;

    ElGamalPK(BigInteger n, BigInteger g, BigInteger h) {
        this.n = n;
        this.g = g;
        this.h = h;
    }
}
