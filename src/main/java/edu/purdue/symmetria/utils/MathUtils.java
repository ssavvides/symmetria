package edu.purdue.symmetria.utils;

import java.math.BigInteger;

public class MathUtils {

    /**
     * Return a random long number in the range -range/2 to range/2
     */
    public static long randLong(long range) {
        return (long) (Math.random() * range - range / 2);
    }

    /**
     * Return a random long number in the range 0 to max
     */
    public static long randLongPos(long max) {
        return (long) (Math.random() * max);
    }

    public static long gcd(long a, long b) {
        return b == 0 ? (a < 0 ? -a : a) : gcd(b, a % b);
    }

    public static long gcdBI(long a, long b) {
        return BigInteger.valueOf(a).gcd(BigInteger.valueOf(b)).longValue();
    }

    /**
     * This function performs the extended euclidean algorithm on two numbers a and b. The function
     * returns the gcd(a,b) as well as the numbers x and y such that ax + by = gcd(a,b). This
     * calculation is important in number theory and can be used for several things such as finding
     * modular inverses and solutions to linear Diophantine equations.
     */
    public static long[] egcd(long a, long b) {
        if (b == 0)
            return new long[]{a < 0 ? -a : a, 1L, 0L};

        long[] v = egcd(b, a % b);
        long tmp = v[1] - v[2] * (a / b);
        v[1] = v[2];
        v[2] = tmp;
        return v;
    }

    public static long mod(long a, long modulo) {
        long r = a % modulo;
        if (r < 0)
            r += modulo;
        return r;
    }

    public static long modBI(long a, long modulo) {
        return BigInteger.valueOf(a).mod(BigInteger.valueOf(modulo)).longValue();
    }

    public static long modAdd(long a, long b, long modulo) {
        a = mod(a, modulo);
        b = mod(b, modulo);
        long r = a + b;
        if (r < 0)
            r += 2;
        return mod(r, modulo);
    }

    public static long modAddBI(long a, long b, long modulo) {
        return BigInteger.valueOf(a).add(BigInteger.valueOf(b)).mod(BigInteger.valueOf(modulo)).longValue();
    }

    public static long modSubtract(long a, long b, long modulo) {
        return modAdd(a, -b, modulo);
    }

    public static long modSubtractBI(long a, long b, long modulo) {
        return BigInteger.valueOf(a).subtract(BigInteger.valueOf(b)).mod(BigInteger.valueOf(modulo)).longValue();
    }

    public static long modNegate(long a, long modulo) {
        return mod(-a, modulo);
    }


    public static long modNegateBI(long a, long modulo) {
        return BigInteger.valueOf(a).negate().mod(BigInteger.valueOf(modulo)).longValue();
    }

    /**
     * source: https://stackoverflow.com/questions/12168348/ways-to-do-modulo-multiplication-with-primitive-types
     */
    public static long modMul(long a, long b, long modulo) {

        if (a == 1)
            return b;
        if (b == 1)
            return a;

        a = mod(a, modulo);
        b = mod(b, modulo);

        if (a == 1)
            return b;
        if (b == 1)
            return a;

        long res = 0;
        long temp_b;

        while (a != 0) {
            if ((a & 1) == 1) {
                // Add b to res, n m, without overflow
                if (b >= modulo - res) // Equiv to if (res + b >= m), without overflow
                    res -= modulo;
                res += b;
            }
            a >>= 1;

            // Double b, n m
            temp_b = b;
            if (b >= modulo - b) // Equiv to if (2 * b >= m), without overflow
                temp_b -= modulo;
            b += temp_b;
        }
        return res;
    }

    public static long modDiv(long a, long b, long modulo) {
        return modMul(a, modInverse(b, modulo), modulo);
    }

    public static long modMulBI(long a, long b, long modulo) {
        return BigInteger.valueOf(a).multiply(BigInteger.valueOf(b)).mod(BigInteger.valueOf(modulo)).longValue();
    }

    public static long modPow(long a, long b, long modulo) {
        return modPowBI(a, b, modulo); // faster
//        if (modulo <= 0)
//            throw new IllegalArgumentException("modulo is less than 0");
//
//        boolean invertResult;
//        if ((invertResult = (b < 0)))
//            b = modNegate(b, modulo);
//
//        a = mod(a, modulo);
//        if (a == 0)
//            return 0;
//        long res = 1;
//        while (b > 0) {
//            if (b % 2 == 1)
//                res = modMul(res, a, modulo);
//            a = modMul(a, a, modulo);
//            b >>= 1;
//        }
//
//        if (invertResult) {
//            if (gcd(res, modulo) != 1) {
//                System.out.println("Attempted to invert BigInteger with no inverse.");
//                return 0;
//            }
//            res = modInverse(res, modulo);
//        }
//
//        return res;
    }

    public static long modPowBI(long a, long b, long modulo) {
        return modPowBI(BigInteger.valueOf(a), BigInteger.valueOf(b), BigInteger.valueOf(modulo)).longValue();
    }

    public static BigInteger modPowBI(BigInteger a, BigInteger b, BigInteger modulo) {
        BigInteger r = BigInteger.ZERO;
        try {
            r = a.modPow(b, modulo);
        } catch (ArithmeticException e) {
            System.out.println("Attempted to invert BigInteger with no inverse.");
        }
        return r;
    }

    /**
     * Returns the modular inverse of 'a' mod 'm' Make sure m > 0 and 'a' & 'm' are relatively
     * prime.
     */
    public static long modInverse(long a, long modulo) {
        a = modAdd(a, modulo, modulo);
        long[] v = egcd(a, modulo);
        long x = v[1];
        return modAdd(x, modulo, modulo);
    }

    public static long modInverseBI(long n, long modulo) {
        return BigInteger.valueOf(n).modInverse(BigInteger.valueOf(modulo)).longValue();
    }

    public static long modPow1(long base, long exponent, long modulus) {
        if (exponent == 0)
            return 1;
        if (exponent == 1)
            return mod(base, modulus);
        if (exponent % 2 == 0) {
            long temp = modPow(base, exponent / 2, modulus);
            return modMul(temp, temp, modulus);
        } else
            return modMul(base, modPow(base, modSubtract(exponent, 1, modulus), modulus), modulus);
    }

    public static long modPow2(long a, long b, long modulo) {
        long res = 1;
        a = mod(a, modulo);
        while (b > 0) {
            if ((b & 1) == 1)
                res = modMul(res, a, modulo);
            b = b >> 1;
            a = modMul(a, a, modulo);
        }
        return res;
    }

    public static long modPow3(long a, long b, long modulo) {
        if (modulo <= 0)
            throw new ArithmeticException("modulo must be > 0");

        // To handle negative exponents use: a^-n mod m = (a^-1)^n mod m
        if (b < 0) {
            if (gcd(a, modulo) != 1)
                throw new ArithmeticException("If n < 0 then must have gcd(a, mod) = 1");
            return modPow(modInverse(a, modulo), mod(-b, modulo), modulo);
        }

        if (b == 0L)
            return 1L;

        long p = a;
        long r = 1L;

        for (long i = 0; b != 0; i++) {
            long mask = 1L << i;
            if ((b & mask) == mask) {
                r = modMul(r, p, modulo);
                r = modAdd(r, modulo, modulo);
                //r = (((r * p) % mod) + mod) % mod;
                b = modSubtract(b, mask, modulo);
            }
            p = modMul(p, p, modulo);
            p = modAdd(p, modulo, modulo);
            //p = ((p * p) % mod + mod) % mod;
        }
        return modAdd(r, modulo, modulo); //(r % mod) + mod) % mod;
    }

    public static long modPow4(long a, long b, long mod) {
        if (mod <= 0)
            throw new IllegalArgumentException("Mod argument is not grater then 0");

        boolean invertResult;
        if ((invertResult = (b < 0)))
            b = modNegate(b, mod);

        a = mod(a, mod);
        if (a == 0)
            return 0;
        long res = 1;
        while (b > 0) {
            if (b % 2 == 1)
                res = modMul(res, a, mod);
            a = modMul(a, a, mod);
            b /= 2;
        }

        if (invertResult) {
            if (gcd(res, mod) != 1) {
                System.out.println("Attempted to invert BigInteger with no inverse.");
                return 0;
            }
            res = modInverse(res, mod);
        } else
            res = mod(res, mod);

        return res;
    }

    public static void testModulo() {

        long iterations = 1000;

        long n = Long.MAX_VALUE;
        long actual, expected;
        for (long i = 0; i >= 0 && i < iterations; i++) {

            long a = randLong(Long.MAX_VALUE);
            long b = randLong(Long.MAX_VALUE);

            // test mod
            actual = mod(a, n);
            expected = modBI(a, n);
            if (actual != expected)
                throw new AssertionError("Mod: Expected=" + expected + " Actual=" + actual);

            // test modAdd
            actual = modAdd(a, b, n);
            expected = modAddBI(a, b, n);
            if (actual != expected)
                throw new AssertionError("ModAdd: Expected=" + expected + " Actual=" + actual);

            // test modSub
            actual = modSubtract(a, b, n);
            expected = modSubtractBI(a, b, n);
            if (actual != expected)
                throw new AssertionError("ModSub: Expected=" + expected + " Actual=" + actual);

            // test modNegate
            actual = modNegate(a, n);
            expected = modNegateBI(a, n);
            if (actual != expected)
                throw new AssertionError("ModNegate: Expected=" + expected + " Actual=" + actual);

            // test modMul
            actual = modMul(a, b, n);
            expected = modMulBI(a, b, n);
            if (actual != expected)
                throw new AssertionError("ModMul: Expected=" + expected + " Actual=" + actual);

            // test modPow
            actual = modPow(a, b, n);
            expected = modPowBI(a, b, n);
            if (actual != expected)
                throw new AssertionError("ModPow: Expected=" + expected + " Actual=" + actual);

            // test gcd
            actual = gcd(a, n);
            expected = gcdBI(a, n);
            if (actual != expected)
                throw new AssertionError("Gcd: Expected=" + expected + " Actual=" + actual);

            // test modInverse
            try {
                expected = modInverseBI(a, n);
            } catch (ArithmeticException e) {
                continue;
            }
            actual = modInverse(a, n);
            if (actual != expected)
                throw new AssertionError("Inverse: Expected=" + expected + " Actual=" + actual);
        }

        System.out.println("Test complete");
    }

    public static void timeModulo() {
        int iterations = 10000;
        int warmup = 100;

        long n = Long.MAX_VALUE;
        long t1 = 0;
        long t2 = 0;
        long ta1 = 0;
        long ta2 = 0;
        long ts1 = 0;
        long ts2 = 0;
        long tm1 = 0;
        long tm2 = 0;
        long tp1 = 0;
        long tp2 = 0;
        long ti1 = 0;
        long ti2 = 0;
        long start;

        for (int i = 0; i < iterations; i++) {
            long a;
            while (true) {
                a = randLong(Long.MAX_VALUE);
                try {
                    MathUtils.modInverseBI(a, n);
                    break;
                } catch (ArithmeticException e) {
                }
            }
            long b = randLong(Long.MAX_VALUE);

            // time mod
            start = System.nanoTime();
            MathUtils.mod(a, n);
            if (i >= warmup)
                t1 += (System.nanoTime() - start);
            start = System.nanoTime();
            MathUtils.modBI(a, n);
            if (i >= warmup)
                t2 += (System.nanoTime() - start);

            // time add
            start = System.nanoTime();
            MathUtils.modAdd(a, b, n);
            if (i >= warmup)
                ta1 += (System.nanoTime() - start);
            start = System.nanoTime();
            MathUtils.modAddBI(a, b, n);
            if (i >= warmup)
                ta2 += (System.nanoTime() - start);

            // time sub
            start = System.nanoTime();
            MathUtils.modSubtract(a, b, n);
            if (i >= warmup)
                ts1 += (System.nanoTime() - start);
            start = System.nanoTime();
            MathUtils.modSubtractBI(a, b, n);
            if (i >= warmup)
                ts2 += (System.nanoTime() - start);

            // time mul
            start = System.nanoTime();
            MathUtils.modMul(a, b, n);
            if (i >= warmup)
                tm1 += (System.nanoTime() - start);
            start = System.nanoTime();
            MathUtils.modMulBI(a, b, n);
            if (i >= warmup)
                tm2 += (System.nanoTime() - start);

            // time pow
            start = System.nanoTime();
            MathUtils.modPow(a, b, n);
            if (i >= warmup)
                tp1 += (System.nanoTime() - start);
            start = System.nanoTime();
            MathUtils.modPowBI(a, b, n);
            if (i >= warmup)
                tp2 += (System.nanoTime() - start);

            // time inv
            start = System.nanoTime();
            MathUtils.modInverse(a, n);
            if (i >= warmup)
                ti1 += (System.nanoTime() - start);
            start = System.nanoTime();
            MathUtils.modInverseBI(a, n);
            if (i >= warmup)
                ti2 += (System.nanoTime() - start);

        }

        System.out.println("Mod");
        System.out.println("T1=" + t1 / (iterations - warmup));
        System.out.println("T2=" + t2 / (iterations - warmup));

        System.out.println("Add");
        System.out.println("T1=" + ta1 / (iterations - warmup));
        System.out.println("T2=" + ta2 / (iterations - warmup));

        System.out.println("Sub");
        System.out.println("T1=" + ts1 / (iterations - warmup));
        System.out.println("T2=" + ts2 / (iterations - warmup));

        System.out.println("Mul");
        System.out.println("T1=" + tm1 / (iterations - warmup));
        System.out.println("T2=" + tm2 / (iterations - warmup));

        System.out.println("Pow");
        System.out.println("T1=" + tp1 / (iterations - warmup));
        System.out.println("T2=" + tp2 / (iterations - warmup));

        System.out.println("Inv");
        System.out.println("T1=" + ti1 / (iterations - warmup));
        System.out.println("T2=" + ti2 / (iterations - warmup));
    }

    public static void main(String[] args) {
        testModulo();
        timeModulo();
    }

}
