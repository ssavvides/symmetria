package edu.purdue.symmetria.crypto;

import edu.purdue.symmetria.utils.FileUtils;

import java.io.File;
import java.security.SecureRandom;

public abstract class CryptoScheme {

    static final int DEFAULT_NEGDIVISOR = 2;
    static final SecureRandom RNG = new SecureRandom();

    final String publicKeyPath;
    final String privateKeyPath;

    final Object publicKey;
    final Object privateKey;

    boolean isSymmetric;

    public CryptoScheme(String privateKeyPath) {

        isSymmetric = true;
        publicKeyPath = null;
        this.privateKeyPath = privateKeyPath;

        // Without the private key we cannot do anything.
        if (this.privateKeyPath == null)
            throw new RuntimeException("Private key path cannot be null in " + "symmetric schemes");

        // if key already exists, use it and don't create new one. Otherwise
        // generate new keys and save them in files.
        if (!keysExist())
            keyGen();

        // read the keys from files.
        publicKey = null;
        privateKey = FileUtils.readObjectFromFile(privateKeyPath);
    }

    public CryptoScheme(String publicKeyPath, String privateKeyPath) {

        isSymmetric = false;
        this.publicKeyPath = publicKeyPath;
        this.privateKeyPath = privateKeyPath;

        // without the public key we cannot do anything.
        if (this.publicKeyPath == null)
            throw new RuntimeException("Public key path cannot be null");

        // if only public key path is given then the public key must exist, it cannot be created since a public key without a private key is useless.
        if (this.privateKeyPath == null && !keysExist())
            throw new RuntimeException("Could not find public key");

        // if keys already exist, use them and don't create new ones. Otherwise generate new keys and save them in files.
        if (this.privateKeyPath != null && !keysExist())
            keyGen();

        // read the keys from files.
        publicKey = FileUtils.readObjectFromFile(publicKeyPath);

        // sometimes a private key might not be provided, i.e in the server side when only the evaluate function is needed.
        if (this.privateKeyPath != null)
            privateKey = FileUtils.readObjectFromFile(privateKeyPath);
        else
            privateKey = null;
    }

    /**
     * Check whether the required keys for the encryption scheme exist.
     *
     * @return true if the required keys exist and false otherwise
     */
    private boolean keysExist() {
        if (!isSymmetric) {
            File publicKey = new File(publicKeyPath);
            if (!publicKey.exists())
                return false;
        }

        if (privateKeyPath != null) {
            File privateKey = new File(privateKeyPath);
            return privateKey.exists();
        }

        return true;
    }

    /**
     * Generate a key for the cipher.
     */
    public abstract void keyGen();

}