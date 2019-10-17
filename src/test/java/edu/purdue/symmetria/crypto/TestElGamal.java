package edu.purdue.symmetria.crypto;

import edu.purdue.symmetria.crypto.cipher.ElGamalCipher;
import edu.purdue.symmetria.utils.MathUtils;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;


public class TestElGamal {
    private static final int ITERATIONS = 10;
    private static final ElGamal SCHEME = new ElGamal();

    @Test
    public void testEncDecr() {
        for (int i = 0; i < ITERATIONS; i++) {
            long ptxt = MathUtils.randLong(1000);
            long decr = SCHEME.decrypt(SCHEME.encrypt(ptxt));
            Assert.assertEquals("Encryption/Decryption failed for SCHEME: "
                    + SCHEME.toString(), ptxt, decr);
        }
    }

    @Test
    public void testMultiply() {
        long m1 = MathUtils.randLong(1000);
        long m2 = MathUtils.randLong(1000);
        long mRes = m1 * m2;
        ElGamalCipher c1 = SCHEME.encrypt(m1);
        ElGamalCipher c2 = SCHEME.encrypt(m2);
        ElGamalCipher cRes = SCHEME.multiply(c1, c2);
        long decr = SCHEME.decrypt(cRes);
        Assert.assertEquals("multiply() failed for scheme: " + SCHEME.toString(),
                mRes, decr);
    }

    @Test
    public void testMultiplyPlaintext() {
        for (int i = 0; i < ITERATIONS; i++) {
            long ptxt1 = MathUtils.randLong(1000);
            long ptxt2 = MathUtils.randLong(1000);
            long ptxtRes = ptxt1 * ptxt2;
            ElGamalCipher ctxt = SCHEME.encrypt(ptxt1);
            ElGamalCipher ctxtRes = SCHEME.multiplyPlaintext(ctxt, ptxt2);
            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("multiplyPlaintext() failed for SCHEME: "
                    + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testDivide() {
        for (int i = 0; i < ITERATIONS; i++) {
            long ptxt2 = (long) (Math.random() * 100) + 1;
            long ptxt1 = ptxt2 * ((long) (Math.random() * 10));
            long ptxtRes = ptxt1 / ptxt2;

            ElGamalCipher ctxt1 = SCHEME.encrypt(ptxt1);
            ElGamalCipher ctxt2 = SCHEME.encrypt(ptxt2);
            ElGamalCipher ctxtRes = SCHEME.divide(ctxt1, ctxt2);
            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("divide() failed for SCHEME: " + SCHEME.toString(), ptxtRes, decr);
        }
    }

    @Test
    public void testPow() {
        for (int i = 0; i < ITERATIONS; i++) {
            long m1 = MathUtils.randLongPos(50);
            long m2 = MathUtils.randLongPos(10);
            long mRes = (long) Math.pow(m1, m2);
            ElGamalCipher ctxt1 = SCHEME.encrypt(m1);
            ElGamalCipher ctxtRes = SCHEME.pow(ctxt1, m2);
            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("pow() failed for SCHEME: " + SCHEME.toString(),
                    mRes, decr);
        }
    }

    @Test
    public void testInverse() {
        for (int i = 0; i < ITERATIONS; i++) {
            // find plaintext with multiplicative modInverse
            BigInteger ptxt;
            BigInteger ptxtRes = null;
            while (true) {
                ptxt = BigInteger.valueOf(MathUtils.randLong(1000));
                try {
                    ptxtRes = ptxt.modInverse(SCHEME.n);
                    ptxtRes = SCHEME.handleNegative(ptxtRes);
                    break;
                } catch (ArithmeticException e) {
                }
            }
            ElGamalCipher ctxt = SCHEME.encrypt(ptxt.longValue());
            ElGamalCipher ctxtRes = SCHEME.inverse(ctxt);
            long decr = SCHEME.decrypt(ctxtRes);
            Assert.assertEquals("modInverse() failed for SCHEME: " + SCHEME.toString(), ptxtRes.longValue(), decr);
        }
    }
}
