package org.openquantumsafe;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class Common {

    private static final String OS = System.getProperty("os.name").toLowerCase();

    public static void wipe(byte[] array) {
        Arrays.fill(array, (byte) 0);
    }

    public static boolean isWindows() {
        return OS.contains("win");
    }

    public static boolean isMac() {
        return OS.contains("mac");
    }

    public static boolean isLinux() {
        return OS.contains("nux");
    }

    public static void loadNativeLibrary() {

        System.loadLibrary("oqs");
        // ^^^ load liboqs manually from java.library.path;
        // oqs-jni depends on it but sometimes is not able to load it on MacOS
        // change by SK

        try {
            System.loadLibrary("oqs-jni");
        // Otherwise load the library from the liboqs-java.jar
        } catch (UnsatisfiedLinkError e) {
            String libName = "liboqs-jni.so";
            if (Common.isLinux()) {
                libName = "liboqs-jni.so";
            } else if (Common.isMac()) {
                libName = "liboqs-jni.jnilib";
            } else if (Common.isWindows()) {
                libName = "oqs-jni.dll";
            }
            URL url = KEMs.class.getResource("/" + libName);
            if (url == null) {
                String[] paths = System.getProperty("java.library.path").split(File.pathSeparator);
                for (String path : paths) {
                    File f = new File(path+File.separator+libName);
                    if (f.isFile()) {
                        try {
                            url = f.toURI().toURL();
                            System.load(url.getFile()); // load from full file name
                            return;
                        } catch (Throwable exception) {
                            exception.printStackTrace();
                        }
                    }
                }
            }

            // try to load from Jar
            File tmpDir;
            try {
                tmpDir = Files.createTempDirectory("oqs-native-lib").toFile();
                tmpDir.deleteOnExit();
                File nativeLibTmpFile = new File(tmpDir, libName);
                nativeLibTmpFile.deleteOnExit();
                InputStream in = url.openStream();
                Files.copy(in, nativeLibTmpFile.toPath());
                System.load(nativeLibTmpFile.getAbsolutePath());
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
    }

    public static <E, T extends Iterable<E>> void print_list(T list) {
        for (Object element : list){
            System.out.print(element);
            System.out.print(" ");
        }
        System.out.println();
    }

    public static String to_hex(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            int v = aByte & 0xFF;
            sb.append(HEX_ARRAY[v >>> 4]);
            sb.append(HEX_ARRAY[v & 0x0F]);
            sb.append(" ");
        }
        return sb.toString();
    }

    public static String chop_hex(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        StringBuilder sb = new StringBuilder();
        int num = 8;
        for (int i = 0; i < num; i++) {
            int v = bytes[i] & 0xFF;
            sb.append(HEX_ARRAY[v >>> 4]);
            sb.append(HEX_ARRAY[v & 0x0F]);
            sb.append(" ");
        }
        if (bytes.length > num*2) {
            sb.append("... ");
        }
        for (int i = bytes.length - num; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            sb.append(HEX_ARRAY[v >>> 4]);
            sb.append(HEX_ARRAY[v & 0x0F]);
            sb.append(" ");
        }
        return sb.toString();
    }

}