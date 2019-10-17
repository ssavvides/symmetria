package edu.purdue.symmetria.crypto;

import edu.purdue.symmetria.crypto.cipher.SymCipher;
import edu.purdue.symmetria.utils.MathUtils;
import org.junit.Assert;
import org.junit.Test;


public class TestSymAHE {
    private static final int ITERATIONS = 1000;
    private static final long RANGE = Long.MAX_VALUE;

    private static final SymAHE SCHEME = new SymAHE();

    @Test
    public void testEncDecr() {
        for (int i = 0; i < ITERATIONS; i++) {
            long ptxt = MathUtils.randLong(RANGE);
            long decr = SCHEME.decrypt(SCHEME.encrypt(ptxt));
            Assert.assertEquals("Encryption/Decryption failed for scheme: "
                    + SCHEME.toString(), ptxt, decr);
        }
    }

    @Test
    public void testAdd() {
        for (int i = 0; i < ITERATIONS; i++) {
            long m1 = MathUtils.randLong(RANGE);
            long m2 = MathUtils.randLong(RANGE);
            long ptxtRes = SCHEME.handleNegative(MathUtils.modAdd(m1, m2, SCHEME.modulo));

            SymCipher c1 = SCHEME.encrypt(m1);
            SymCipher c2 = SCHEME.encrypt(m2);
            SymCipher cRes = SCHEME.add(c1, c2);
            long decr = SCHEME.decrypt(cRes);
            Assert.assertEquals("add() failed for scheme: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testAddPlaintext() {
        for (int i = 0; i < ITERATIONS; i++) {
            long m1 = MathUtils.randLong(RANGE);
            long m2 = MathUtils.randLong(RANGE);
            long ptxtRes = SCHEME.handleNegative(MathUtils.modAdd(m1, m2, SCHEME.modulo));
            SymCipher ctxtRes = SCHEME.addPlaintext(SCHEME.encrypt(m1), m2);
            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("addPlaintext() failed for scheme: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testSubtract() {
        for (int i = 0; i < ITERATIONS; i++) {
            long m1 = MathUtils.randLong(RANGE);
            long m2 = MathUtils.randLong(RANGE);
            long ptxtRes = SCHEME.handleNegative(MathUtils.modSubtract(m1, m2, SCHEME.modulo));

            SymCipher c1 = SCHEME.encrypt(m1);
            SymCipher c2 = SCHEME.encrypt(m2);
            SymCipher ctxtRes = SCHEME.subtract(c1, c2);
            long decr = SCHEME.decrypt(ctxtRes);

            Assert.assertEquals("subtract() failed for scheme: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testMultiply() {
        for (int i = 0; i < ITERATIONS; i++) {
            long ptxt1 = MathUtils.randLong(RANGE);
            long ptxt2 = MathUtils.randLong(RANGE);
            long ptxtRes = SCHEME.handleNegative(MathUtils.modMul(ptxt1, ptxt2, SCHEME.modulo));

            SymCipher ctxtRes = SCHEME.multiply(SCHEME.encrypt(ptxt1), ptxt2);
            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("multiply() failed for scheme: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testNegate() {
        for (int i = 0; i < ITERATIONS; i++) {
            long ptxt = MathUtils.randLong(RANGE);
            long ptxtRes = -ptxt;
            SymCipher ctxtRes = SCHEME.negate(SCHEME.encrypt(ptxt));
            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("negate() failed for scheme: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testSum() {
        long pSum = MathUtils.randLong(RANGE);
        SymCipher cSum = SCHEME.encrypt(pSum);
        for (int i = 0; i < ITERATIONS; i++) {
            long m = MathUtils.randLong(RANGE);
            SymCipher c = SCHEME.encrypt(m);

            pSum = MathUtils.modAdd(pSum, m, SCHEME.modulo);
            cSum = SCHEME.add(cSum, c);

            long pRes = SCHEME.handleNegative(pSum);
            long cRes = SCHEME.decrypt(cSum);

            Assert.assertEquals("testSum() failed for scheme: " + SCHEME.toString(), pRes, cRes);
        }
    }

    @Test
    public void testProd() {
        long pProd = MathUtils.randLong(RANGE);
        SymCipher cProd = SCHEME.encrypt(pProd);
        for (int i = 0; i < ITERATIONS; i++) {
            long m = MathUtils.randLong(RANGE);
            pProd = MathUtils.modMul(pProd, m, SCHEME.modulo);
            cProd = SCHEME.multiply(cProd, m);
            long pRes = SCHEME.handleNegative(pProd);
            long cRes = SCHEME.decrypt(cProd);
            Assert.assertEquals("testProd() failed for scheme: " + SCHEME.toString(), pRes, cRes);
        }
    }

    @Test
    public void testMulti() {
        long modulo = SCHEME.modulo;
        long ptxtRes = MathUtils.randLong(RANGE);
        SymCipher res = SCHEME.encrypt(ptxtRes);

        for (int i = 0; i < ITERATIONS; i++) {
            long m = MathUtils.randLong(RANGE);
            SymCipher c = SCHEME.encrypt(m);

            int op = (int) (Math.random() * 4);
            if (op == 0) {
                res = SCHEME.add(res, c);
                ptxtRes = MathUtils.modAdd(ptxtRes, m, modulo);

                long p = SCHEME.handleNegative(ptxtRes % modulo);
                long d = SCHEME.decrypt(res);
                Assert.assertEquals("Multi (+) failed for scheme: "
                        + SCHEME.toString(), p, d);

            } else if (op == 1) {
                res = SCHEME.subtract(res, c);
                ptxtRes = MathUtils.modSubtract(ptxtRes, m, modulo);

                long p = SCHEME.handleNegative(ptxtRes % modulo);
                long d = SCHEME.decrypt(res);
                Assert.assertEquals("Multi (-) failed for scheme: "
                        + SCHEME.toString(), p, d);

            } else if (op == 2) {
                res = SCHEME.addPlaintext(res, m);
                ptxtRes = MathUtils.modAdd(ptxtRes, m, modulo);

                long p = SCHEME.handleNegative(ptxtRes % modulo);
                long d = SCHEME.decrypt(res);
                Assert.assertEquals("Multi (+p) failed for scheme: "
                        + SCHEME.toString(), p, d);

            } else if (op == 3) {
                res = SCHEME.multiply(res, m);
                ptxtRes = MathUtils.modMul(ptxtRes, m, modulo);

                long p = SCHEME.handleNegative(ptxtRes % modulo);
                long d = SCHEME.decrypt(res);
                Assert.assertEquals("Multi (*) failed for scheme: "
                        + SCHEME.toString() + " for * " + m, p, d);

            } else if (op == 4) {
                res = SCHEME.negate(res);
                ptxtRes = MathUtils.modNegate(ptxtRes, modulo);

                long p = SCHEME.handleNegative(ptxtRes % modulo);
                long d = SCHEME.decrypt(res);
                Assert.assertEquals("Multi (~) failed for scheme: "
                        + SCHEME.toString(), p, d);

            } else
                Assert.fail();

            ptxtRes = SCHEME.handleNegative(ptxtRes % modulo);
            long decr = SCHEME.decrypt(res);
            Assert.assertEquals("Multi failed for scheme: "
                    + SCHEME.toString(), ptxtRes, decr);
        }
    }
}
