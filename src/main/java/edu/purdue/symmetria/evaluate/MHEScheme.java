package edu.purdue.symmetria.evaluate;

import edu.purdue.symmetria.crypto.ElGamal;
import edu.purdue.symmetria.crypto.SymMHE;
import edu.purdue.symmetria.crypto.cipher.ElGamalCipher;
import edu.purdue.symmetria.crypto.cipher.SymCipher;
import edu.purdue.symmetria.utils.MathUtils;

public class MHEScheme {

    private static final int WARMUP = 10;
    private static final int ITERATIONS = 100;

    private static final SymMHE symMHE = new SymMHE();
    private static final ElGamal elgamal = new ElGamal();

    public enum MHEOp {
        ENCRYPT, DECRYPT, MULTIPLY, MULTIPLY_PLAINTEXT, DIVIDE, POW, INVERSE
    }

    public static void timeOp(MHEOp op) {

        System.out.println("\nEvaluating " + op.name() + " ...");

        long startTime;
        long symMHETime = 0;
        long elgamalTime = 0;
        for (int i = 0; i < ITERATIONS + WARMUP; i++) {

            long m1 = MathUtils.randLong(1_000_000);
            long m2 = MathUtils.randLong(1_000_000);

            // if needed get messages that have modInverse
            if (op == MHEOp.INVERSE) {
                while (true) {
                    m1 = MathUtils.randLong(1_000_000);
                    try {
                        MathUtils.modInverse(m1, symMHE.modulo);
                        break;
                    } catch (ArithmeticException e) {
                    }
                }
            }

            SymCipher c_mhe1 = symMHE.encrypt(m1);
            SymCipher c_mhe2 = symMHE.encrypt(m2);
            ElGamalCipher c_elgamal1 = elgamal.encrypt(m1);
            ElGamalCipher c_elgamal2 = elgamal.encrypt(m2);

            switch (op) {
                case ENCRYPT:
                    startTime = System.nanoTime();
                    symMHE.encrypt(m1);
                    if (i >= WARMUP)
                        symMHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    elgamal.encrypt(m1);
                    if (i >= WARMUP)
                        elgamalTime += (System.nanoTime() - startTime);
                    break;

                case DECRYPT:
                    startTime = System.nanoTime();
                    symMHE.decrypt(c_mhe1);
                    if (i >= WARMUP)
                        symMHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    elgamal.decrypt(c_elgamal1);
                    if (i >= WARMUP)
                        elgamalTime += (System.nanoTime() - startTime);
                    break;

                case MULTIPLY:
                    startTime = System.nanoTime();
                    symMHE.multiply(c_mhe1, c_mhe2);
                    if (i >= WARMUP)
                        symMHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    elgamal.multiply(c_elgamal1, c_elgamal2);
                    if (i >= WARMUP)
                        elgamalTime += (System.nanoTime() - startTime);
                    break;

                case MULTIPLY_PLAINTEXT:
                    startTime = System.nanoTime();
                    symMHE.multiplyPlaintext(c_mhe1, m2);
                    if (i >= WARMUP)
                        symMHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    elgamal.multiplyPlaintext(c_elgamal1, m2);
                    if (i >= WARMUP)
                        elgamalTime += (System.nanoTime() - startTime);
                    break;

                case DIVIDE:
                    startTime = System.nanoTime();
                    symMHE.divide(c_mhe1, c_mhe2);
                    if (i >= WARMUP)
                        symMHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    elgamal.divide(c_elgamal1, c_elgamal2);
                    if (i >= WARMUP)
                        elgamalTime += (System.nanoTime() - startTime);
                    break;

                case POW:
                    m2 = MathUtils.randLongPos(10);
                    startTime = System.nanoTime();
                    symMHE.pow(c_mhe1, m2);
                    if (i >= WARMUP)
                        symMHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    elgamal.pow(c_elgamal1, m2);
                    if (i >= WARMUP)
                        elgamalTime += (System.nanoTime() - startTime);
                    break;

                case INVERSE:
                    startTime = System.nanoTime();
                    symMHE.inverse(c_mhe1);
                    if (i >= WARMUP)
                        symMHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    elgamal.inverse(c_elgamal1);
                    if (i >= WARMUP)
                        elgamalTime += (System.nanoTime() - startTime);
                    break;

                default:
                    System.out.println("Unexpected operation");
                    System.exit(1);
            }
        }

        symMHETime = symMHETime / ITERATIONS;
        elgamalTime = elgamalTime / ITERATIONS;

        System.out.println("symMHE\tElGamal (nanoseconds)");
        System.out.println(symMHETime + "\t" + elgamalTime);
    }


    public static void main(String[] args) {
        for (MHEOp op : MHEOp.values())
            timeOp(op);
    }

}
