package edu.purdue.symmetria.crypto;


import edu.purdue.symmetria.crypto.cipher.SymCipher;
import edu.purdue.symmetria.crypto.cipher.SymCipher.CipherType;
import edu.purdue.symmetria.utils.FileUtils;
import edu.purdue.symmetria.utils.MathUtils;

import java.math.BigInteger;

public class SymAHE extends SymPHE {

    private static final String DEFAULT_KEY_PATH = "/tmp/symahe.sk";

    public SymAHE() {
        this(DEFAULT_CIPHER_TYPE, CryptoScheme.DEFAULT_NEGDIVISOR, DEFAULT_KEY_PATH);
    }

    public SymAHE(CipherType type) {
        this(type, CryptoScheme.DEFAULT_NEGDIVISOR, DEFAULT_KEY_PATH);
    }

    public SymAHE(int negDivisor) {
        this(DEFAULT_CIPHER_TYPE, negDivisor, DEFAULT_KEY_PATH);
    }

    public SymAHE(String path) {
        this(DEFAULT_CIPHER_TYPE, CryptoScheme.DEFAULT_NEGDIVISOR, path);
    }

    public SymAHE(CipherType type, int negDivisor, String privateKeyPath) {
        super(type, negDivisor, privateKeyPath);
        modulo = Long.MAX_VALUE;
        moduloBI = BigInteger.valueOf(modulo);
        setupNegative(negDivisor);
    }

    @Override
    public void keyGen() {
        String key = new BigInteger(128, RNG).toString(32);
        FileUtils.saveObjectToFile(key, privateKeyPath);
    }

    @Override
    public SymCipher encrypt(long m) {
        long nextId = getNextId();
        long v = MathUtils.modAdd(m, getRandNum(nextId, this.modulo), this.modulo);
        return SymPHE.generateCipher(cipherType, v, nextId);
    }

    @Override
    public long decrypt(SymCipher c) {
        long m = c.getValue();
        long[][] ids = c.getIds();
        for (int i = 0; i < c.getSize(); i++) {
            long id = ids[0][i];
            long card = ids[1][i];
            long obf = getRandNum(id, modulo);
            if (card < 0)
                m = MathUtils.modAdd(m, MathUtils.modMul(obf, -card, modulo), modulo);
            else
                m = MathUtils.modSubtract(m, MathUtils.modMul(obf, card, modulo), modulo);
        }
        return handleNegative(m);
    }

    public SymCipher add(SymCipher c1, SymCipher c2) {
        c1.add(c2, this.modulo);
        return c1;
    }

    public SymCipher addPlaintext(SymCipher c, long m) {
        c.addValue(m, this.modulo);
        return c;
    }

    public SymCipher subtract(SymCipher c1, SymCipher c2) {
        return this.add(c1, this.negate(c2));
    }

    public SymCipher multiply(SymCipher c, long m) {
        c.multiply(m, this.modulo);
        return c;
    }

    public SymCipher negate(SymCipher c) {
        return this.multiply(c, -1l);
    }

    @Override
    public String toString() {
        return "<" + this.getClass().getSimpleName() + ">";
    }
}
