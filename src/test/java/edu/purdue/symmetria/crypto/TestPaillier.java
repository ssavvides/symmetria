package edu.purdue.symmetria.crypto;

import edu.purdue.symmetria.utils.MathUtils;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;


public class TestPaillier {
    private static final int ITERATIONS = 10;
    private static final Paillier SCHEME = new Paillier();

    @Test
    public void testEncDecr() {
        for (int i = 0; i < ITERATIONS; i++) {
            long ptxt = MathUtils.randLong(1000);
            long decr = SCHEME.decrypt(SCHEME.encrypt(ptxt));
            Assert.assertEquals("Encryption/Decryption failed for scheme: "
                    + SCHEME.toString(), ptxt, decr);
        }
    }

    @Test
    public void testAdd() {
        for (int i = 0; i < ITERATIONS; i++) {
            long m1 = MathUtils.randLong(1000);
            long m2 = MathUtils.randLong(1000);
            long ptxtRes = m1 + m2;

            BigInteger c1 = SCHEME.encrypt(m1);
            BigInteger c2 = SCHEME.encrypt(m2);
            BigInteger cRes = SCHEME.add(c1, c2);
            long decr = SCHEME.decrypt(cRes);
            Assert.assertEquals("add() failed for scheme: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testAddPlaintext() {
        for (int i = 0; i < ITERATIONS; i++) {
            long ptxt1 = MathUtils.randLong(1000);
            long ptxt2 = MathUtils.randLong(1000);
            long ptxtRes = ptxt1 + ptxt2;
            BigInteger ctxtRes = SCHEME.addPlaintext(SCHEME.encrypt(ptxt1), ptxt2);
            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("addPlaintext() failed for scheme: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testSubtract() {
        for (int i = 0; i < ITERATIONS; i++) {
            long ptxt1 = MathUtils.randLong(1000);
            long ptxt2 = MathUtils.randLong(1000);
            long ptxtRes = ptxt1 - ptxt2;
            BigInteger ctxtRes = SCHEME.subtract(SCHEME.encrypt(ptxt1), SCHEME.encrypt(ptxt2));
            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("subtract() failed for scheme: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testMultiply() {
        for (int i = 0; i < ITERATIONS; i++) {
            long ptxt1 = MathUtils.randLong(1000);
            long ptxt2 = MathUtils.randLong(1000);
            long ptxtRes = ptxt1 * ptxt2;
            BigInteger ctxtRes = SCHEME.multiply(SCHEME.encrypt(ptxt1), ptxt2);
            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("multiply() failed for scheme: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testNegate() {
        for (int i = 0; i < ITERATIONS; i++) {
            long ptxt = MathUtils.randLong(1000);
            long ptxtRes = -ptxt;
            BigInteger ctxtRes = SCHEME.negate(SCHEME.encrypt(ptxt));
            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("negate() failed for scheme: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    /*
    @Crypto
    public void testOperations() {
        for (int i = 0; i < ITER; i++) {

            BigInteger ptxtRes = BigInteger.valueOf((long) (Math.random() * 1000));
            BigInteger ctxtRes = paillier.encrypt(ptxtRes);
            int numberOfOperations = 20;
            for (int opNo = 0; opNo < numberOfOperations; opNo++) {

                BigInteger ptxt = BigInteger.valueOf((long) (Math.random() * 1000));
                BigInteger ctxt = paillier.encrypt(ptxt);

                int opType = (int) (Math.random() * 3);
                if (opType == 0) {
                    ptxtRes = ptxtRes.add(ptxt);
                    ctxtRes = paillier.add(ctxtRes, ctxt);
                } else if (opType == 1) {
                    ptxtRes = ptxtRes.subtract(ptxt);
                    ctxtRes = paillier.subtract(ctxtRes, ctxt);
                } else {
                    ptxtRes = ptxtRes.multiply(ptxt);
                    ctxtRes = paillier.multiply(ctxtRes, ptxt.intValue());
                }
            }

            BigInteger decr = paillier.decrypt(ctxtRes);
            Assert.assertEquals("Mixed operations of paillier failed", ptxtRes, decr);
        }
    }
    */
}
