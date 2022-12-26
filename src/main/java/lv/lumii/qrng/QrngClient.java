package lv.lumii.qrng;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;

import org.bouncycastle.pqc.InjectablePQC;
import org.graalvm.word.WordFactory;
import org.slf4j.*;

import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.graalvm.nativeimage.IsolateThread;
import org.graalvm.nativeimage.UnmanagedMemory;
import org.graalvm.nativeimage.c.function.CEntryPoint;
import org.graalvm.nativeimage.c.struct.SizeOf;
import org.graalvm.nativeimage.c.type.CCharPointer;

import javax.net.ssl.SSLContext;

public class QrngClient {

    public static Logger logger;

    public static CCharPointer NULL_BUFFER;
    private static String mainExecutable;
    private static String mainDirectory;

    private static QrngProperties qrngProperties;
    private static ClientBuffer clientBuffer;
    private static QrngServer qrngServer;

    static {

        try {
             NULL_BUFFER = WordFactory.nullPointer(); // user from GraalVM native image
        }
        catch (Exception e) {
            NULL_BUFFER = null; // used from Java mode of GraalVM
        }

        InjectablePQC.inject();

        /*
        do not use log4j2 in native executables/libraries!!!
        slf4j with simple logger is ok;

        gradle dependencies:
            implementation 'org.slf4j:slf4j-api:2.+'
            implementation 'org.slf4j:slf4j-simple:2.+'
         */

        File f = new File(QrngClient.class.getProtectionDomain().getCodeSource().getLocation().getPath());
        mainExecutable = f.getAbsolutePath();
        mainDirectory = f.getParent();

        // Fix for debug purposes when qrng-client is launched from the IDE:
        if (mainExecutable.replace('\\', '/').endsWith("/build/classes/java/main")) {
            mainDirectory = mainExecutable.substring(0, mainExecutable.length()-"/build/classes/java/main".length());
            mainExecutable = "java";
        }
        String logFileName = mainDirectory+File.separator+"qrng.log";
        System.setProperty("org.slf4j.simpleLogger.logFile", logFileName);
        logger = LoggerFactory.getLogger(QrngClient.class);

        qrngProperties = new QrngProperties(mainDirectory);
        clientBuffer = new ClientBuffer(qrngProperties.clientBufferSize());

        qrngServer = new QrngServer(qrngProperties, clientBuffer);

        try {
            qrngProperties.clientToken().certificateChain();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        Provider tlsProvider = null;
        try {
            tlsProvider = SSLContext.getInstance("TLS").getProvider();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        logger.debug("Using TLS provider: "+tlsProvider.getName()); // BCJSSE

        //System.load("/Users/sergejs/.sdkman/candidates/java/current/lib/libosxsecurity.dylib");
        //System.load("/Users/sergejs/graalvm-ce-java17-22.3.0/Contents/Home/lib/libosxsecurity.dylib");
        //System.loadLibrary("osxsecurity");


        /*BouncyCastleJsseProvider jsseProvider = new BouncyCastleJsseProvider();
        Security.insertProviderAt(jsseProvider, 1);

        BouncyCastlePQCProvider bcProvider = new BouncyCastlePQCProvider(); // BCPQC
        Security.insertProviderAt(bcProvider, 1);*/
    }


    @CEntryPoint(name = "qrng_get_main_executable")
    public static synchronized CCharPointer qrng_get_main_executable(IsolateThread thread) {
        return toCCharPointer(mainExecutable);
    }


    @CEntryPoint(name = "qrng_connect")
    public static synchronized void qrng_connect(IsolateThread thread) {
        logger.debug("java.library.path="+System.getProperty("java.library.path"));
        qrngServer.ensureReplenishing(0);
    }

    @CEntryPoint(name = "qrng_get_random_bytes")
    public static synchronized CCharPointer qrng_get_random_bytes(IsolateThread thread, CCharPointer targetBuffer, int count) {
        if (count<0)
            return toCCharPointer("{\"error\":\"Negative count specified\"}");

        qrngServer.ensureReplenishing(0);

        try {
            byte[] bytes = clientBuffer.consume(count);
            if (targetBuffer==NULL_BUFFER) {
                // converting bytes to Java stream:
                var buffer = ByteBuffer.wrap(bytes);
                var bytesStr = Stream.generate(() -> buffer.get()).
                        limit(buffer.capacity()).
                        map(b -> Byte.toString(b)).
                        collect(Collectors.joining(" "));
                throw new RuntimeException("{\"error\":\"QrngClient is not running within Native Image. "+
                        "However, the QRNG service is working. We got "+count+" random bytes: "+bytesStr+".\"");
            }
            for (int i = 0; i < count; ++i) {
                targetBuffer.write(i, bytes[i]);
            }
            // All OK
            return NULL_BUFFER; // Java "null" won't work in Native Image!
        } catch (InterruptedException e) {
            if (targetBuffer == NULL_BUFFER) {
                throw new RuntimeException("{\"error\":\"QrngClient is not running within Native Image. We are here to report an exception: "+e.getMessage()+"\"}");
            }
            return toCCharPointer("{\"error\":\"Waiting for random bytes was interrupted: "+e.getMessage()+"\"}");
        }

    }

    /**
     * Technical function to transform Java String to CCharPointer (char*) that can be returned to C.
     * The result must be freed by calling qrng_free_result.
     * @param string the Java string to transform
     * @return a CCharPointer that will be returned to C as char*
     */
    private static CCharPointer toCCharPointer(String string) {
        byte[] bytes = string.getBytes(StandardCharsets.UTF_8);
        CCharPointer charPointer = UnmanagedMemory.calloc(
                (bytes.length + 1) * SizeOf.get(CCharPointer.class));
        for (int i = 0; i < bytes.length; ++i) {
            charPointer.write(i, bytes[i]);
        }
        charPointer.write(bytes.length, (byte) 0);
        return charPointer;
    }

    @CEntryPoint(name = "qrng_free_result")
    protected static synchronized void qrng_free_result(
            IsolateThread thread, CCharPointer result
    ) {
        if (result.isNonNull())
            UnmanagedMemory.free(result);
    }

}
