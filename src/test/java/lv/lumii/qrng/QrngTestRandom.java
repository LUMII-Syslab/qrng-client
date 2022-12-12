package lv.lumii.qrng;

import org.graalvm.nativeimage.c.type.CCharPointer;

public class QrngTestRandom {

    public static void main(String[] args) throws Exception {

        QrngClient.qrng_connect(null);

        // Here will be exceptions regarding writing to targetBuffer, which is null and cannot be used from Java
        // (but only from an executable compiled by GraalVM Native Image).
        // Still, we can use this code to debug QrngClient.
        CCharPointer res = QrngClient.qrng_get_random_bytes(null, QrngClient.NULL_BUFFER, 10);

    }


}
