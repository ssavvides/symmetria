package edu.purdue.symmetria.utils;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.Base64;

public class ByteUtils {
    private static ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    public static byte[] longToBytesBB(long x) {
        buffer.putLong(0, x);
        return buffer.array();
    }

    public static long bytesToLongBB(byte[] bytes) {
        buffer.put(bytes, 0, bytes.length);
        buffer.flip(); //need flip
        return buffer.getLong();
    }

    public static byte[] longToBytes(long l) {
        byte[] result = new byte[Long.BYTES];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte) (l & 0xFF);
            l >>= Byte.SIZE;
        }
        return result;
    }

    /**
     * Converts a byte array to a long number. Uses the first 8 bytes.
     */
    public static long bytesToLong(byte[] b) {
        long result = 0;
        for (int i = 0; i < Long.BYTES; i++) {
            result <<= Byte.SIZE;
            result |= (b[i] & 0xFF);
        }
        return result;
    }

    /**
     * Serialize an object to a byte array
     */
    public static byte[] serialize(Object obj) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream os = null;
        try {
            os = new ObjectOutputStream(out);
            os.writeObject(obj);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return out.toByteArray();
    }

    /**
     * Deserialize an object from a byte array.
     */
    public static Object deserialize(byte[] data) {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is;
        Object result = null;
        try {
            is = new ObjectInputStream(in);
            result = is.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Encode a byte array to a base 64 string
     */
    public static String base64Encode(byte[] bytes) {
        // remove trailing '=' characters (padding). Careful if ever want to concatenate these.
        return ENCODER.encodeToString(bytes).replaceAll("=+$", "").trim();
    }

    /**
     * Decode a base 64 string to a byte array
     */
    public static byte[] base64Decode(String str) {
        return DECODER.decode(str);
    }

}