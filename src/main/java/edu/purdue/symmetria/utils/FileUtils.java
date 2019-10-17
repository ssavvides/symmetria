package edu.purdue.symmetria.utils;

import java.io.*;

public class FileUtils {

    /**
     * Given an object and a file path, generate a file and store that object.
     *
     * @param obj      the object to save
     * @param filePath the file path of the file in which the object will be saved.
     */
    public static void saveObjectToFile(Object obj, String filePath) {
        // Save secret key to files.
        ObjectOutputStream keyOS = null;
        try {
            File file = new File(filePath);

            // if parent directories don't exist, create them.
            if (file.getParentFile() != null) {
                file.getParentFile().mkdirs();
            }

            // create a new file and write the object to it.
            file.createNewFile();
            keyOS = new ObjectOutputStream(new FileOutputStream(file));
            keyOS.writeObject(obj);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                keyOS.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Given a file path, returns the object stored in that file.
     *
     * @param filePath the path to the file from which a single object will be read.
     * @return the object read from the file path given
     */
    public static Object readObjectFromFile(String filePath) {
        ObjectInputStream inputStream = null;
        Object obj = null;

        try {
            inputStream = new ObjectInputStream(new FileInputStream(filePath));
            obj = inputStream.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (inputStream != null)
                    inputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return obj;
    }
}
