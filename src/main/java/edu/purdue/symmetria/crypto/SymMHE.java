package edu.purdue.symmetria.crypto;

import edu.purdue.symmetria.crypto.cipher.SymCipher;
import edu.purdue.symmetria.crypto.cipher.SymCipher.CipherType;
import edu.purdue.symmetria.utils.FileUtils;
import edu.purdue.symmetria.utils.MathUtils;

import java.math.BigInteger;

public class SymMHE extends SymPHE {

    private static final String DEFAULT_KEY_PATH = "/tmp/symmhe.sk";
    private static final long DEFAULT_MODULO = 9222730058745388403L;
    private static final long DEFAULT_GENERATOR = 6980122786781000881L;

    public long g;
    // g as a BigInteger
    public BigInteger gBI;


    public SymMHE() {
        this(DEFAULT_CIPHER_TYPE, CryptoScheme.DEFAULT_NEGDIVISOR, DEFAULT_KEY_PATH);
    }

    public SymMHE(CipherType type) {
        this(type, CryptoScheme.DEFAULT_NEGDIVISOR, DEFAULT_KEY_PATH);
    }

    public SymMHE(int negDivisor) {
        this(DEFAULT_CIPHER_TYPE, negDivisor, DEFAULT_KEY_PATH);
    }

    public SymMHE(String path) {
        this(DEFAULT_CIPHER_TYPE, CryptoScheme.DEFAULT_NEGDIVISOR, path);
    }

    public SymMHE(CipherType type, int negDivisor, String privateKeyPath) {
        super(type, negDivisor, privateKeyPath);

        // generateModulo();
        modulo = DEFAULT_MODULO;
        moduloBI = BigInteger.valueOf(modulo);
        g = DEFAULT_GENERATOR;
        gBI = BigInteger.valueOf(g);

        setupNegative(negDivisor);
    }

    private void generateModulo() {
        moduloBI = BigInteger.probablePrime(Long.SIZE - 1, CryptoScheme.RNG);
        modulo = moduloBI.longValue();
        do {
            gBI = BigInteger.probablePrime(Long.SIZE - 1, CryptoScheme.RNG);
        } while (gBI.compareTo(moduloBI) >= 0 || !gBI.gcd(moduloBI).equals(BigInteger.ONE));
        g = gBI.longValue();
    }

    @Override
    public void keyGen() {
        String key = new BigInteger(128, CryptoScheme.RNG).toString(32);
        FileUtils.saveObjectToFile(key, privateKeyPath);
    }

    @Override
    public SymCipher encrypt(long m) {
        long nextId = getNextId();
        long obf = MathUtils.modPow(g, getRandNum(nextId, modulo), modulo);
        long v = MathUtils.modMul(m, obf, modulo);
        return SymPHE.generateCipher(cipherType, v, nextId);
    }

    @Override
    public long decrypt(SymCipher c) {
        long m = c.getValue();
        long[][] ids = c.getIds();
        for (int i = 0; i < c.getSize(); i++) {
            long r = getRandNum(ids[0][i], modulo);
            long obf = MathUtils.modPow(g, r, modulo);
            long card = ids[1][i];
            if (card >= 0)
                obf = MathUtils.modInverse(obf, modulo);
            else
                card = MathUtils.modNegate(card, modulo);
            if (card != 1)
                obf = MathUtils.modPow(obf, card, modulo);
            m = MathUtils.modMul(m, obf, modulo);
        }
        return handleNegative(m);
    }

    public SymCipher multiply(SymCipher c1, SymCipher c2) {
        c1.multiply(c2, this.modulo);
        return c1;
    }

    public SymCipher multiplyPlaintext(SymCipher c, long m) {
        c.multiplyValue(m, this.modulo);
        return c;
    }

    public SymCipher divide(SymCipher c1, SymCipher c2) {
        return this.multiply(c1, this.inverse(c2));
    }

    public SymCipher pow(SymCipher c, long m) {
        c.pow(m, modulo);
        return c;
    }

    public SymCipher inverse(SymCipher c) {
        return this.pow(c, -1L);
    }

    @Override
    public String toString() {
        return "<" + this.getClass().getSimpleName() + ">";
    }
}
