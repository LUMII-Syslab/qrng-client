package lv.lumii.qrng;

import nl.altindag.ssl.SSLFactory;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import javax.net.ssl.*;
import java.io.*;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

public class QrngConnectionTest {

    public static void main(String[] args) throws Exception {

        BouncyCastleJsseProvider jsseProvider = new BouncyCastleJsseProvider();
        Security.insertProviderAt(jsseProvider, 1);

        BouncyCastlePQCProvider bcProvider = new BouncyCastlePQCProvider(); // BCPQC
        Security.insertProviderAt(bcProvider, 1);


        Provider tlsProvider = SSLContext.getInstance("TLS").getProvider();
        System.out.println("Using TLS provider: "+tlsProvider.getName()); // BCJSSE

        String host = "ws.qrng.lumii.lv";
        int port = 443;

        for (Provider prov : Security.getProviders()) {
            System.out.println("PROVIDER "+prov.getName());
        }

        KeyStore clientKeyStore  = KeyStore.getInstance("PKCS12");// Algorithm HmacPBESHA256 not available => need jdk16 (new pkx format hash)
        FileInputStream instream = new FileInputStream(new File("/Users/sergejs/quantum.gits/qrng-client/token.keystore")); //V2
        try {
            //clientKeyStore.load(instream, "123456".toCharArray()); // V1
            clientKeyStore.load(instream, "token-pass".toCharArray()); // V2
        }
        catch (Exception e) {
            e.printStackTrace();
            System.out.println("CLIENT KEY STORE EXCEPTION");
            return;
        }
        finally {
            instream.close();
        }


        KeyStore trustStore;
        try {
            trustStore = KeyStore.getInstance(new File("/Users/sergejs/quantum.gits/qrng-client/ca.truststore"), "ca-truststore-pass".toCharArray());
        }
        catch (Exception e) {
            e.printStackTrace();
            return;
        }

        KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("SunX509");
        //keyMgrFact.init(clientKeyStore, "123456".toCharArray()); // V1
        keyMgrFact.init(clientKeyStore, "token-pass".toCharArray()); // V2

        TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");
        trustMgrFact.init(trustStore);

        // OLD WAY
        /*

        SSLContext clientContext = SSLContext.getInstance("TLSv1.3");
        clientContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), SecureRandom.getInstanceStrong());
        SSLSocketFactory fact = clientContext.getSocketFactory();
        SSLSocket ssl = (SSLSocket)fact.createSocket(host, port);

        ssl.setUseClientMode(true);*/




        // NEW WAY
        SSLFactory sslf2 = SSLFactory.builder()

                //.withIdentityMaterial(keyMgrFact)
                .withIdentityMaterial(clientKeyStore.getKey("qrng_client", "token-pass".toCharArray()), "token-pass".toCharArray(), clientKeyStore.getCertificateChain("qrng_client"))
                .withProtocols("TLSv1.3")
                //.withIdentityRoute("localhost", host)// "localhost")
                .withTrustMaterial(trustMgrFact)
                .withSecureRandom(SecureRandom.getInstanceStrong())
                .withCiphers("TLS_AES_256_GCM_SHA384")
                .build();




        SSLSocket ssl2 = (SSLSocket) sslf2.getSslSocketFactory().createSocket(host, port);//(host, port)



        final SSLSocket myssl = ssl2; // ssl or ssl2

        // sslParams are important for our SNI proxy (we need to set the server name)
        SSLParameters sslParams = new SSLParameters();
        sslParams.setEndpointIdentificationAlgorithm("HTTPS");

        List<SNIServerName> list = new LinkedList<>();
        list.add(new SNIHostName(host));
        sslParams.setServerNames(list);
        sslParams.setWantClientAuth(true);
        sslParams.setNeedClientAuth(true);
        sslParams.setCipherSuites(new String[] {"TLS_AES_256_GCM_SHA384"}); // ???

        myssl.setSSLParameters(sslParams);

        // from: https://github.com/TooTallNate/Java-WebSocket

        WebSocketClient cln = new WebSocketClient(new URI("wss://" + host + ":" + port)) {

            private long callId = 1;

            private byte[] intToBytes(int x) {
                ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
                buffer.putInt(x);
                return buffer.array();
            }

            private byte[] bytesFor1024 = intToBytes(3*1024);
            private byte[] bytesFor512 = intToBytes(3*512);
            private byte[] bytesFor0 = intToBytes(0);

            // TODO: 1x in a second check the client buffer and send binary request on how many bytes are still needed to fulfill the buffer
            // send that number (and wait patiently for onMessage(blob))
            // SEE: https://stackoverflow.com/questions/12908412/print-hello-world-every-x-seconds

            @Override
            protected void onSetSSLParameters(SSLParameters sslParameters) {
                super.onSetSSLParameters(sslParameters);
                List<SNIServerName> list = new LinkedList<>();
                System.out.println("setting host name "+host);
                list.add(new SNIHostName(host));
                sslParameters.setServerNames(list);
                sslParameters.setWantClientAuth(true);
                sslParameters.setNeedClientAuth(true);
                sslParameters.setCipherSuites(new String[] {"TLS_AES_256_GCM_SHA384"}); // ???
            }

            @Override
            public void onOpen(ServerHandshake serverHandshake) {
                System.out.println("OPENED WS");

                // send as json-rpc notification; receive 1024-byte block
                //this.getConnection().send("{\"jsonrpc\": \"2.0\", \"method\": \"consume\", \"id\": "+this.callId+" }");
                /*this.getConnection().send(bytesFor1024);
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }*/
                this.getConnection().send(bytesFor1024);
                this.getConnection().send(bytesFor512);
                this.getConnection().send(bytesFor0);
                callId++;
            }

            @Override
            public void onMessage(String s) {
                System.out.println("TXT MSG WS: ["+s+"]");
            }

            @Override
            public void onMessage(ByteBuffer blob) {
                System.out.println("BYTE MSG WS: ["+blob.array().length+" bytes]");
                //this.getConnection().send("{\"jsonrpc\": \"2.0\", \"method\": \"consume\", \"id\": "+this.callId+" }");
                //this.getConnection().send(bytesFor1024);
                callId++;
            }

            @Override
            public void onClose(int i, String s, boolean b) {
                System.out.println("CLOSED WS ["+s+"]");
            }

            @Override
            public void onError(Exception e) {
                System.out.println("Error "+e.getMessage());
                e.printStackTrace();
            }

        };

        cln.setConnectionLostTimeout(20);
        cln.setSocketFactory(sslf2.getSslSocketFactory());

        boolean b = false;
        // DEPRECATED setSocket
        if (b) {
            cln.setSocket(myssl);
        }
        else {
            cln.run();
        }

        // MANUAL HANDSHAKE
        if (b) {
            myssl.addHandshakeCompletedListener((ev) -> {
                try {
                    System.out.println("HANDSHAKE DONE");


                    OutputStream os = myssl.getOutputStream();
                    String s = //"GET /index.html HTTP/1.0\n"+
                            "GET / HTTP/1.1\n" + // 1.1 is important (1.0 will not work!)
                                    //"Host: localhost:4433\n"+
                                    "Host: " + host + ":" + port + "\n" +
                                    "Upgrade: websocket\n" +
                                    "Connection: Upgrade\n" +
                                    "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\n" +
                                    "Sec-WebSocket-Protocol: chat, superchat\n" +
                                    "Sec-WebSocket-Version: 13\n\n";
                    //Origin: http://example.com
                            /*"Sec-WebSocket-Key: haproxy\n"+
                            "Sec-WebSocket-Version: 13\n"+
                            "Sec-WebSocket-Protocol: echo-protocol\n"+*/
                    //"User-Agent: curl/7.54.0\n"+
                    //"Accept: */*\n\n"; // ! important two \n
                    // Connection:\ Upgrade\r\nUpgrade:\ websocket\r\nSec-WebSocket-Key:\ haproxy\r\nSec-WebSocket-Version:\ 13\r\nSec-WebSocket-Protocol:\ echo-protocol


                    os.write(s.getBytes(StandardCharsets.UTF_8));
                    os.flush();
                    os.write(QrngConnectionTest.intToBytes(1024));
                    os.flush();

                    InputStream is = myssl.getInputStream();
                    BufferedReader input = new BufferedReader(
                            new InputStreamReader(is));

                    for (; ; ) {
                        System.out.println("READING...");
                        String ss = input.readLine();
                        if (ss == null)
                            break;
                        System.out.println("RESPONSE LINE: " + ss);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            myssl.startHandshake();
        }




        // TODO: apache hc 5 client to use bouncycastle SSL socket factory

        // see: https://github.com/apache/httpcomponents-client/blob/5.1.x/httpclient5/src/test/java/org/apache/hc/client5/http/examples/ClientConfiguration.java
        // https://hc.apache.org/httpcomponents-client-5.1.x/migration-guide/index.html

        /*TODO: Protocol myhttps = new Protocol("https", new fact, 4433);;
        HttpClient client = HttpClients.createDefault();
        client.HttpClients.custom(). .custom(). .setSSLSocketFactory(sslConnectionSocketFactory).build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI("https://127.0.0.1:4433"))
                //.version(HttpClient.Version.HTTP_2)
                .GET()
                .build();

        HttpClient client = HttpClient
                .newBuilder()

                //.socketFactory(
                .proxy(ProxySelector.getDefault())
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println("SMART RESPONSE: "+response.body());

         */
    }

    private static byte[] intToBytes(int x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putInt(x);
        return buffer.array();
    }

}
