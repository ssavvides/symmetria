package edu.purdue.symmetria.crypto;

import edu.purdue.symmetria.utils.FileUtils;

import java.io.Serializable;
import java.math.BigInteger;

public class Paillier extends AsymPHE<BigInteger> {

    private static final String DEFAULT_PUBLIC_KEY_PATH = "/tmp/paillier.pk";
    private static final String DEFAULT_PRIVATE_KEY_PATH = "/tmp/paillier.sk";

    // load keys
    private BigInteger n2; // n squared
    private BigInteger g;
    private BigInteger mu;
    private BigInteger lambda; // private key

    // precomputed random
    private BigInteger preRand;

    public Paillier() {
        this(DEFAULT_NEGDIVISOR, DEFAULT_PUBLIC_KEY_PATH, DEFAULT_PRIVATE_KEY_PATH);
    }

    public Paillier(int negDivisor, String publicKeyPath, String privateKeyPath) {
        super(publicKeyPath, privateKeyPath);

        PaillierPK pk = (PaillierPK) publicKey;
        n = pk.n;
        n2 = pk.n2;
        g = pk.g;
        mu = pk.mu;
        lambda = (BigInteger) privateKey;

        if (!ENABLE_RANDOM)
            preRand = new BigInteger(BITLENGTH, RNG).modPow(n, n2);

        setupNegative(negDivisor);
    }

    public void keyGen() {
        BigInteger p = BigInteger.probablePrime(BITLENGTH / 2, RNG);
        BigInteger q;
        do {
            q = BigInteger.probablePrime(BITLENGTH / 2, RNG);
        } while (p.equals(q));

        BigInteger n = p.multiply(q);
        BigInteger n2 = n.multiply(n);

        // lambda = lcm(n-1, q-1) = (n-1)*(q-1)/gcd(n-1, q-1).
        BigInteger p1 = p.subtract(BigInteger.ONE);
        BigInteger q1 = q.subtract(BigInteger.ONE);
        BigInteger lambda = p1.multiply(q1).divide(p1.gcd(q1));

        // verify g, the following must hold: gcd(L(g^lambda mod n^2), n) = 1, where L(u) = (u-1)/n
        BigInteger g;
        do {
            g = BigInteger.probablePrime(BITLENGTH, RNG);
        } while (g.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1);
        BigInteger mu = g.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).modInverse(n);

        FileUtils.saveObjectToFile(lambda, privateKeyPath);
        FileUtils.saveObjectToFile(new PaillierPK(n, n2, g, mu), publicKeyPath);
    }

    @Override
    public BigInteger encrypt(long m) {
        BigInteger rn = preRand;
        if (ENABLE_RANDOM)
            rn = new BigInteger(BITLENGTH, RNG).modPow(n, n2);
        BigInteger gm = g.modPow(BigInteger.valueOf(m), n2);
        return gm.multiply(rn).mod(n2);
    }

    // adds 32 bits of padding before each number. This allows for a total of 21 messages per packed message.
    private BigInteger pack(long[] messages) {
        BigInteger packedMessage = BigInteger.ZERO;
        BigInteger shift = BigInteger.valueOf(2).multiply(BigInteger.valueOf(95 /*64 + 21*/));
        for (long m : messages) {
            packedMessage = packedMessage.multiply(shift);
            packedMessage = packedMessage.add(BigInteger.valueOf(m));
        }
        return packedMessage;
    }

    // assume there are exactly 21 items in packed message.
    private long[] unpack(BigInteger packedMessage) {
        long[] messages = new long[21];
        BigInteger shift = BigInteger.valueOf(2).multiply(BigInteger.valueOf(95 /* 64 + 21 */));
        for (int i = 0; i < 21; i++) {
            BigInteger message = packedMessage.mod(shift);
            messages[i] = message.longValue(); // assume no overflow
            packedMessage = packedMessage.divide(shift);
        }
        return messages;
    }

    public BigInteger encryptPacked(long[] messages) {
        BigInteger rn = preRand;
        if (ENABLE_RANDOM)
            rn = new BigInteger(BITLENGTH, RNG).modPow(n, n2);
        BigInteger packedMessage = pack(messages);
        BigInteger gm = g.modPow(packedMessage, n2);
        return gm.multiply(rn).mod(n2);
    }

    public long[] decryptPacked(BigInteger c) {
        BigInteger m = c.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).multiply(mu).mod(n);
        return unpack(m);
    }

    @Override
    public long decrypt(BigInteger c) {
        BigInteger m = c.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).multiply(mu).mod(n);
        return handleNegative(m).longValue();
    }

    public BigInteger add(BigInteger c1, BigInteger c2) {
        return c1.multiply(c2).mod(n2);
    }

    public BigInteger addPlaintext(BigInteger c, long m) {
        return c.multiply(g.modPow(BigInteger.valueOf(m), n2)).mod(n2);
    }

    public BigInteger addPlaintextPacked(BigInteger c, long[] m) {
        return c.multiply(g.modPow(pack(m), n2)).mod(n2);
    }

    public BigInteger subtract(BigInteger c1, BigInteger c2) {
        return add(c1, negate(c2));
    }

    public BigInteger multiply(BigInteger c, long m) {
        return c.modPow(BigInteger.valueOf(m), n2);
    }

    public BigInteger negate(BigInteger ciphertext) {
        return multiply(ciphertext, -1l);
    }

    @Override
    public String toString() {
        return "<Paillier modLength=" + BITLENGTH + ">";
    }

    public static byte[] toBytes(BigInteger c) {
        return c.toByteArray();
    }

    public static BigInteger fromBytes(byte[] bytes) {
        return new BigInteger(bytes);
    }
}

class PaillierPK implements Serializable {

    final BigInteger n;
    final BigInteger n2;
    final BigInteger g;
    final BigInteger mu;

    PaillierPK(BigInteger n, BigInteger n2, BigInteger g, BigInteger mu) {
        this.n = n;
        this.n2 = n2;
        this.g = g;
        this.mu = mu;
    }

}