package edu.purdue.symmetria.evaluate;

import edu.purdue.symmetria.crypto.Paillier;
import edu.purdue.symmetria.crypto.SymAHE;
import edu.purdue.symmetria.crypto.SymPHE;
import edu.purdue.symmetria.crypto.cipher.SymCipher;
import edu.purdue.symmetria.utils.MathUtils;

import java.math.BigInteger;

public class AHEScheme {

    private static final int WARMUP = 2;
    private static final int ITERATIONS = 20 + WARMUP;

    public static SymAHE symAHE = new SymAHE();
    public static Paillier paillier = new Paillier();

    public enum AHEOp {
        ENCRYPT, DECRYPT, ADD, ADD_PLAINTEXT, SUBTRACT, MULTIPLY, NEGATE
    }

    public static void timeOp(AHEOp op) {

        System.out.println("\nEvaluating " + op.name() + " ...");

        long startTime;
        long symAHETime = 0;
        long paillierTime = 0;
        for (int i = 0; i < ITERATIONS; i++) {
            long m1 = MathUtils.randLong(1_000_000);
            long m2 = MathUtils.randLong(1_000_000);

            SymCipher c_ahe1 = symAHE.encrypt(m1);
            SymCipher c_ahe2 = symAHE.encrypt(m2);
            BigInteger c_paillier1 = paillier.encrypt(m1);
            BigInteger c_paillier2 = paillier.encrypt(m2);

            switch (op) {
                case ENCRYPT:
                    startTime = System.nanoTime();
                    symAHE.encrypt(m1);
                    if (i >= WARMUP)
                        symAHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    paillier.encrypt(m1);
                    if (i >= WARMUP)
                        paillierTime += (System.nanoTime() - startTime);
                    break;

                case DECRYPT:
                    startTime = System.nanoTime();
                    symAHE.decrypt(c_ahe1);
                    if (i >= WARMUP)
                        symAHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    paillier.decrypt(c_paillier1);
                    if (i >= WARMUP)
                        paillierTime += (System.nanoTime() - startTime);
                    break;

                case ADD:
                    startTime = System.nanoTime();
                    symAHE.add(c_ahe1, c_ahe2);
                    if (i >= WARMUP)
                        symAHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    paillier.add(c_paillier1, c_paillier2);
                    if (i >= WARMUP)
                        paillierTime += (System.nanoTime() - startTime);
                    break;

                case ADD_PLAINTEXT:
                    startTime = System.nanoTime();
                    symAHE.addPlaintext(c_ahe1, m2);
                    if (i >= WARMUP)
                        symAHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    paillier.addPlaintext(c_paillier1, m2);
                    if (i >= WARMUP)
                        paillierTime += (System.nanoTime() - startTime);
                    break;

                case SUBTRACT:
                    startTime = System.nanoTime();
                    symAHE.subtract(c_ahe1, c_ahe2);
                    if (i >= WARMUP)
                        symAHETime += (System.nanoTime() - startTime);
                    startTime = System.nanoTime();

                    paillier.subtract(c_paillier1, c_paillier2);
                    if (i >= WARMUP)
                        paillierTime += (System.nanoTime() - startTime);
                    break;

                case MULTIPLY:
                    startTime = System.nanoTime();
                    symAHE.multiply(c_ahe1, m2);
                    if (i >= WARMUP)
                        symAHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    paillier.multiply(c_paillier1, m2);
                    if (i >= WARMUP)
                        paillierTime += (System.nanoTime() - startTime);
                    break;

                case NEGATE:
                    startTime = System.nanoTime();
                    symAHE.negate(c_ahe1);
                    if (i >= WARMUP)
                        symAHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    paillier.negate(c_paillier1);
                    if (i >= WARMUP)
                        paillierTime += (System.nanoTime() - startTime);
                    break;

                default:
                    System.out.println("Unexpected operation");
                    System.exit(1);
            }
        }

        symAHETime = symAHETime / (ITERATIONS - WARMUP);
        paillierTime = paillierTime / (ITERATIONS - WARMUP);

        System.out.println("SymAHE\tPaillier");
        System.out.println(symAHETime + "\t" + paillierTime);
    }


    public static void main(String[] args) {
        for (AHEOp op : AHEOp.values())
            timeOp(op);
    }

}
