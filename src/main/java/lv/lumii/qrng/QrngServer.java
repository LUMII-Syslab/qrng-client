package lv.lumii.qrng;

import nl.altindag.ssl.SSLFactory;
import org.cactoos.Scalar;
import org.cactoos.scalar.Sticky;
import org.cactoos.scalar.Synced;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.slf4j.Logger;

import javax.net.ssl.TrustManagerFactory;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class QrngServer {

    public static Logger logger = QrngClient.logger; // one common logger

    private QrngProperties qrngProperties;
    private ClientBuffer clientBuffer;

    private Scalar<WebSocketClient> wsclient;
    ScheduledExecutorService reconnectService;


    public QrngServer(QrngProperties qrngProperties1, ClientBuffer clientBuffer) {
        System.out.println(" New QrngServer");
        qrngProperties = qrngProperties1;
        this.clientBuffer = clientBuffer;
        this.wsclient = new Synced<>(new Sticky<>(() -> newConnection() ));
        this.reconnectService = Executors.newSingleThreadScheduledExecutor();
    }

    private WebSocketClient newConnection() throws Exception {

        System.out.println(" New connection ");

        QrngClientToken token = qrngProperties.clientToken();

        System.out.println("TOKEN "+token.password()+" "+token.certificateChain());

        TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");
        trustMgrFact.init(qrngProperties.trustStore());

        SSLFactory sslf2 = SSLFactory.builder()
                .withIdentityMaterial(token.key(), token.password(), token.certificateChain())
                .withProtocols("TLSv1.3")
                .withTrustMaterial(trustMgrFact)
                .withSecureRandom(SecureRandom.getInstanceStrong())
                .withCiphers("TLS_AES_256_GCM_SHA384")
                .build();



        WebSocketClient cln = new WebSocketClient(new URI("wss://" + qrngProperties.host() + ":" + qrngProperties.port())) {
            // ^^^ see also: https://github.com/TooTallNate/Java-WebSocket

            ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();

            @Override
            public void onOpen(ServerHandshake serverHandshake) {
                executorService.scheduleAtFixedRate(()->checkAndReplenish(), 0, 1, TimeUnit.SECONDS);
            }

            @Override
            public void onMessage(String s) {
                // text message: do nothing!
            }

            @Override
            public void onMessage(ByteBuffer blob) {
                // binary message: replenish the buffer
                clientBuffer.replenishWith(blob.array());
            }

            @Override
            public void onClose(int i, String s, boolean b) {
                logger.info("Connection with the server closed: "+s);
                executorService.shutdownNow();

                ensureReplenishing(10);
            }

            @Override
            public void onError(Exception e) {
                logger.error("Connection with the server lost: "+e.getMessage(), e);
            }
        };


        cln.setConnectionLostTimeout(20);
        cln.setSocketFactory(sslf2.getSslSocketFactory());
        System.out.println(" Starting run...");
        new Thread(()->cln.run()).start();
        // ^^^ cln.run() is blocking => we launch it in a new thread
        System.out.println(" run started");

        return cln;
    }

    public synchronized void ensureReplenishing(int afterSeconds) {

        //System.load("/Users/sergejs/.sdkman/candidates/java/current/lib/libosxsecurity.dylib");
        //System.loadLibrary("osxsecurity");
        System.out.println(" ensureReplenishing started");

        boolean isClosed;
        try {
            isClosed = this.wsclient.value().isClosed();
        } catch (Exception e) {
            logger.error("Web socket connection error", e);
            return;
        }

        if (isClosed) {
            reconnectService.shutdownNow();
            logger.info("Reconnecting in " + afterSeconds + " seconds...");
            reconnectService.schedule(() -> {
                logger.info("Reconnecting...");
                try {
                    this.wsclient.value().reconnect();
                } catch (Exception e) {
                    logger.error("Web socket connection error during reconnect", e);
                }
            }, afterSeconds, TimeUnit.SECONDS);
        }
    }

    private void checkAndReplenish() {
        int unused = clientBuffer.unusedCapacity();
        // it is OK if unused==0; we then send 0 to the server in order to inform it about the full client buffer
        byte[] bytes = intToBytes(unused);
        try {
            wsclient.value().getConnection().send(bytes);
        } catch (Exception e) {
            QrngClient.logger.error("Could not request "+unused+" bytes from the QRNG server", e);
        }
    };

    private byte[] intToBytes(int x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putInt(x);
        return buffer.array();
    }

}
