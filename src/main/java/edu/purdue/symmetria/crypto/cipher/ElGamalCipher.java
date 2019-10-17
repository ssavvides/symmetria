package edu.purdue.symmetria.crypto.cipher;

import java.io.Serializable;
import java.math.BigInteger;

public class ElGamalCipher implements Serializable {
    public BigInteger c1;
    public BigInteger c2;

    public ElGamalCipher(BigInteger c1, BigInteger c2) {
        this.c1 = c1;
        this.c2 = c2;
    }
}
