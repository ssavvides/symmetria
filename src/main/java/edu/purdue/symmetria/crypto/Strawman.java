package edu.purdue.symmetria.crypto;

import edu.purdue.symmetria.utils.ByteUtils;
import edu.purdue.symmetria.utils.FileUtils;

import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class Strawman extends CryptoScheme {

    private static final String DEFAULT_KEY_PATH = "/tmp/aes-rnd.sk";
    private static final int BITLENGTH = 128;
    private static final String CHARSET_NAME = "UTF-8";

    private static final String ALGORITHM = "AES";
    private Cipher cipherEncrypt;
    private Cipher cipherDecrypt;

    public Strawman() {
        this(DEFAULT_KEY_PATH);
    }

    public Strawman(String privateKeyPath) {
        super(privateKeyPath);

        // initialize encryption and decryption ciphers
        try {
            this.cipherEncrypt = Cipher.getInstance(ALGORITHM, "SunJCE");
            this.cipherDecrypt = Cipher.getInstance(ALGORITHM, "SunJCE");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException("Unable to initialize AES cipher");
        }
    }

    @Override
    public void keyGen() {
        KeyGenerator kgen = null;

        try {
            kgen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // set the size of the key.
        kgen.init(BITLENGTH);

        SecretKey skeySpec = kgen.generateKey();

        // save key to file
        FileUtils.saveObjectToFile(skeySpec, privateKeyPath);
    }

    public String encrypt(long plaintext) {
        String plaintextStr = Long.toString(plaintext);
        byte[] ciphertext = null;

        byte[] iv = new byte[16];
        RNG.nextBytes(iv);
        try {
            this.cipherEncrypt.init(Cipher.ENCRYPT_MODE, (SecretKey) this.privateKey);
            ciphertext = this.cipherEncrypt.doFinal(plaintextStr.getBytes(CHARSET_NAME));
        } catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException
                | InvalidKeyException e) {
            e.printStackTrace();
        }

        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        byteBuffer.put(iv);
        byteBuffer.put(ciphertext);
        byte[] cipher = byteBuffer.array();
        return ByteUtils.base64Encode(cipher);
    }

    public long decryptSingle(String cipher) {
        byte[] ctxtBA = ByteUtils.base64Decode(cipher);

        ByteBuffer byteBuffer = ByteBuffer.wrap(ctxtBA);
        byte[] iv = new byte[16];
        byteBuffer.get(iv);
        byte[] ciphertext = new byte[byteBuffer.remaining()];
        byteBuffer.get(ciphertext);

        byte[] plaintext = null;
        try {
            this.cipherDecrypt.init(Cipher.DECRYPT_MODE, (SecretKey) this.privateKey);
            plaintext = this.cipherDecrypt.doFinal(ciphertext);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return Integer.parseInt(new String(plaintext, StandardCharsets.UTF_8));
    }

    public long compute(char op, long c1, long c2) {
        long result;
        switch (op) {
            case '+':
                result = c1 + c2;
                break;
            case '-':
                result = c1 - c2;
                break;
            case '*':
                result = c1 * c2;
                break;
            default:
                throw new RuntimeException("Invalid op `" + op + "`");
        }
        return result;
    }

    public long decrypt(String cipher) {
        if (!cipher.contains("("))
            return decryptSingle(cipher);

        // extract op
        char op = cipher.charAt(0);
        // get remaining string
        cipher = cipher.substring(2, cipher.length() - 1);

        // get index c1 ends
        int brackets = 0;
        int index = 0;
        while (cipher.charAt(index) != ',' || brackets != 0) {
            if (cipher.charAt(index) == '(')
                brackets++;
            if (cipher.charAt(index) == ')')
                brackets--;
            if (brackets < 0)
                throw new RuntimeException("Something went wrong");
            index++;
        }

        // extract c1 and c2
        String c1 = cipher.substring(0, index);
        String c2 = cipher.substring(index + 1);
        return compute(op, decrypt(c1), decrypt(c2));
    }

    public String homOp(String op, String c1, String c2) {
        return op + "(" + c1 + "," + c2 + ")";
    }

    public String add(String c1, String c2) {
        return homOp("+", c1, c2);
    }

    public String sub(String c1, String c2) {
        return homOp("-", c1, c2);
    }

    public String multiply(String c1, String c2) {
        return homOp("*", c1, c2);
    }


    public static void main(String[] args) {
        Strawman strawman = new Strawman();
        int m1 = 5;
        int m2 = 10;
        int m3 = 9;
        int m4 = 4;
        String c1 = strawman.encrypt(m1);
        String c2 = strawman.encrypt(m2);
        String c3 = strawman.encrypt(m3);
        String c4 = strawman.encrypt(m4);
        String r1 = strawman.add(c1, c2);
        String r2 = strawman.sub(c3, c4);
        String r3 = strawman.multiply(r1, r2);
        System.out.println(r3);
        System.out.println(strawman.decrypt(r3));
    }
}
