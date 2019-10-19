package edu.purdue.symmetria.evaluate;

import edu.purdue.symmetria.crypto.Paillier;
import edu.purdue.symmetria.crypto.Strawman;
import edu.purdue.symmetria.crypto.SymAHE;
import edu.purdue.symmetria.crypto.cipher.RangeSymCipher;
import edu.purdue.symmetria.crypto.cipher.SymCipher;
import edu.purdue.symmetria.utils.MathUtils;

import java.math.BigInteger;


public class Sum {
    private static int ITERATIONS = 10_000;


    private static void timeSum() {

        // print headers
        System.out.println("Count\tSelectivity"
                + "\tSymAHE(time)\tStrawman(time)\tPaillier(time)"
                + "\tSymAHE(size)\tStrawman(size)\tPaillier(size)");

        int selectivity = 1;
        while (selectivity <= 100) {

            SymAHE symAHE = new SymAHE();
            Paillier paillier = new Paillier();
            Strawman strawman = new Strawman();

            long startTime;
            long symAHETime = 0;
            long strawmanTime = 0;
            long paillierTime = 0;

            // init sums
            long count = 0;
            SymCipher sum_sahe = symAHE.encrypt(0);
            String sum_straw = strawman.encrypt(0);
            BigInteger sum_paillier = paillier.encrypt(0);

            // Paillier encrypt is slow so encrypt only once here
            BigInteger c_paillier = paillier.encrypt(100);

            for (int i = 0; i < ITERATIONS; i++) {

                long m = MathUtils.randLong(1000);

                // encrypt sahe in every iteration regardless of selectivity
                // so the internal index changes
                SymCipher c_sahe = symAHE.encrypt(m);

                int select = (int) (Math.random() * 100);
                if (select < selectivity) {

                    count += 1;
                    String c_straw = strawman.encrypt(m);

                    startTime = System.nanoTime();
                    sum_sahe = symAHE.add(sum_sahe, c_sahe);
                    symAHETime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    sum_straw = strawman.add(sum_straw, c_straw);
                    strawmanTime += (System.nanoTime() - startTime);

                    startTime = System.nanoTime();
                    sum_paillier = paillier.add(sum_paillier, c_paillier);
                    paillierTime += (System.nanoTime() - startTime);
                }
            }

            int size_sahe = ((RangeSymCipher) sum_sahe).byteSize();
            int size_straw = sum_straw.getBytes().length;
            int size_paillier = sum_paillier.toByteArray().length;

            System.out.println(
                    count + "\t" + selectivity + "\t"
                            + symAHETime + "\t" + strawmanTime + "\t" + paillierTime + "\t"
                            + size_sahe + "\t" + size_straw + "\t" + size_paillier
            );

            // set selectivity to = 1, 10, 20, 30, ...
            // selectivity of 1 is just warmup
            if (selectivity == 1)
                selectivity = 10;
            else
                selectivity += 10;
        }
    }


    public static void main(String[] args) {
        timeSum();
    }
}
