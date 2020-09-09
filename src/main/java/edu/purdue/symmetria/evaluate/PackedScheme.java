package edu.purdue.symmetria.evaluate;

import edu.purdue.symmetria.crypto.Paillier;
import edu.purdue.symmetria.utils.MathUtils;

import java.math.BigInteger;

public class PackedScheme {

    private static final int WARMUP = 10;
    private static final int ITERATIONS = 100;
    private static final int PACKED_LENGTH = 21;

    private static final Paillier paillier = new Paillier();

    public enum AHEOp {
        ENCRYPT, DECRYPT, ADD, ADD_PLAINTEXT
    }

    private static void timeOp(AHEOp op) {

        System.out.println("\nEvaluating " + op.name() + " ... (nanoseconds)");

        long startTime;
        long paillierTime = 0;

        for (int i = 0; i < ITERATIONS + WARMUP; i++) {

            long[] m1 = new long[PACKED_LENGTH];
            long[] m2 = new long[PACKED_LENGTH];
            for (int j = 0; j < PACKED_LENGTH; j++) {
                m1[j] = MathUtils.randLong(1_000_000);
                m2[j] = MathUtils.randLong(1_000_000);
            }
            BigInteger c_paillier1 = paillier.encryptPacked(m1);
            BigInteger c_paillier2 = paillier.encryptPacked(m2);

            switch (op) {
                case ENCRYPT:
                    startTime = System.nanoTime();
                    paillier.encryptPacked(m1);
                    if (i >= WARMUP)
                        paillierTime += (System.nanoTime() - startTime);
                    break;

                case DECRYPT:
                    startTime = System.nanoTime();
                    paillier.decrypt(c_paillier1);
                    if (i >= WARMUP)
                        paillierTime += (System.nanoTime() - startTime);
                    break;

                case ADD:
                    startTime = System.nanoTime();
                    paillier.add(c_paillier1, c_paillier2);
                    if (i >= WARMUP)
                        paillierTime += (System.nanoTime() - startTime);
                    break;

                case ADD_PLAINTEXT:
                    startTime = System.nanoTime();
                    paillier.addPlaintextPacked(c_paillier1, m2);
                    if (i >= WARMUP)
                        paillierTime += (System.nanoTime() - startTime);
                    break;

                default:
                    System.out.println("Unexpected operation");
                    System.exit(1);
            }
        }

        paillierTime = paillierTime / ITERATIONS / PACKED_LENGTH;

        System.out.println(paillierTime);
    }


    public static void main(String[] args) {
        for (AHEOp op : AHEOp.values())
            timeOp(op);
    }

}
