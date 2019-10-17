package edu.purdue.symmetria.crypto;

import edu.purdue.symmetria.crypto.cipher.SymCipher;
import edu.purdue.symmetria.utils.MathUtils;
import org.junit.Assert;
import org.junit.Test;


public class TestSymMHE {
    private static final int ITERATIONS = 1000;

    private static final SymMHE SCHEME = new SymMHE();

    private static final long RANGE = SCHEME.modulo;


    @Test
    public void testMultiply() {
        for (int i = 0; i < ITERATIONS; i++) {
            long m1 = MathUtils.randLong(RANGE);
            long m2 = MathUtils.randLong(RANGE);

            long ptxtRes = SCHEME.handleNegative(MathUtils.modMul(m1, m2, SCHEME.modulo));

            SymCipher ctxtRes = SCHEME.multiply(SCHEME.encrypt(m1), SCHEME.encrypt(m2));
            long decr = SCHEME.decrypt(ctxtRes);

            Assert.assertEquals("multiply() failed for SCHEME: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testMultiplyPlaintext() {
        for (int i = 0; i < ITERATIONS; i++) {
            long m1 = MathUtils.randLong(RANGE);
            long m2 = MathUtils.randLong(RANGE);

            long mRes = SCHEME.handleNegative(MathUtils.modMul(m1, m2, SCHEME.modulo));
            SymCipher ctxtRes = SCHEME.multiplyPlaintext(SCHEME.encrypt(m1), m2);

            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("multiplyPlaintext() failed for SCHEME: "
                    + SCHEME.toString(), mRes, decr);
        }
    }

    @Test
    public void testDivide() {
        for (int i = 0; i < ITERATIONS; i++) {
            long m1 = MathUtils.randLong(RANGE);
            long m2 = MathUtils.randLong(RANGE);

            long ptxtRes = SCHEME.handleNegative(MathUtils.modDiv(m1, m2, SCHEME.modulo));

            SymCipher ctxtRes = SCHEME.divide(SCHEME.encrypt(m1), SCHEME.encrypt(m2));
            long decr = SCHEME.decrypt(ctxtRes);

            Assert.assertEquals("divide() failed for SCHEME: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testPow() {
        for (int i = 0; i < ITERATIONS; i++) {
            long m1 = MathUtils.randLong(RANGE);
            long m2 = MathUtils.randLongPos(10);

            long mRes = SCHEME.handleNegative(MathUtils.modPow(m1, m2, SCHEME.modulo));

            SymCipher ctxtRes = SCHEME.pow(SCHEME.encrypt(m1), m2);
            long decr = SCHEME.decrypt(ctxtRes);

            Assert.assertEquals("pow() failed for SCHEME: " + SCHEME.toString(), mRes, decr);
        }
    }

    @Test
    public void testInverse() {
        for (int i = 0; i < ITERATIONS; i++) {
            // find plaintext with multiplicative modInverse
            long ptxt;
            long ptxtRes;
            while (true) {
                ptxt = MathUtils.randLong(RANGE);
                try {
                    ptxtRes = MathUtils.modInverse(ptxt, SCHEME.modulo);
                    ptxtRes = SCHEME.handleNegative(ptxtRes);
                    break;
                } catch (ArithmeticException e) {
                }
            }
            SymCipher ctxtRes = SCHEME.inverse(SCHEME.encrypt(ptxt));
            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("modInverse() failed for SCHEME: " + SCHEME.toString(), ptxtRes, decr);
        }
    }


    @Test
    public void testProd() {
        long pSum = MathUtils.randLong(RANGE);
        SymCipher cSum = SCHEME.encrypt(pSum);
        for (int i = 0; i < ITERATIONS; i++) {
            long m = MathUtils.randLong(RANGE);
            SymCipher c = SCHEME.encrypt(m);

            pSum = MathUtils.modMul(pSum, m, SCHEME.modulo);
            cSum = SCHEME.multiply(cSum, c);

            long pRes = SCHEME.handleNegative(pSum);
            long cRes = SCHEME.decrypt(cSum);

            Assert.assertEquals("testProd() failed for scheme: " + SCHEME.toString(), pRes, cRes);
        }
    }

    @Test
    public void testMulti() {
        long modulo = SCHEME.modulo;
        long ptxtRes = MathUtils.randLong(RANGE);
        SymCipher res = SCHEME.encrypt(ptxtRes);

        for (int i = 0; i < ITERATIONS; i++) {
            long m = MathUtils.randLongPos(100000);
            SymCipher c = SCHEME.encrypt(m);

            int op = (int) (Math.random() * 4);
            if (op == 0) {
                res = SCHEME.multiply(res, c);
                ptxtRes = MathUtils.modMul(ptxtRes, m, modulo);
            } else if (op == 1) {
                res = SCHEME.divide(res, c);
                ptxtRes = MathUtils.modDiv(ptxtRes, m, modulo);
            } else if (op == 2) {
                res = SCHEME.multiplyPlaintext(res, m);
                ptxtRes = MathUtils.modMul(ptxtRes, m, modulo);
            } else if (op == 3) {
                // TODO: FAILS FOR LARGE VALUES
            } else if (op == 4) {
                res = SCHEME.inverse(res);
                ptxtRes = MathUtils.modInverse(ptxtRes, modulo);
            } else
                Assert.fail();

            Assert.assertEquals("Multi failed for scheme: "
                    + SCHEME.toString(), SCHEME.handleNegative(ptxtRes), SCHEME.decrypt(res));
        }
    }
}
