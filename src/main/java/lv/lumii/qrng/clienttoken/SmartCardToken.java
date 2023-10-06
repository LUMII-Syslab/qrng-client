package lv.lumii.qrng.clienttoken;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class SmartCardToken implements Token {

    public static class DummyPrivateKey {
        private final PrivateKey privateKey;

        public DummyPrivateKey() {
            // Generate an RSA key pair (public and private keys)
            KeyPairGenerator keyPairGenerator = null;
            try {
                keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            keyPairGenerator.initialize(1024);
            // ^^^ some not too big key size (but also not too small; otherwise, the generator throws an exception)

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Extract the private key from the key pair
            privateKey = keyPair.getPrivate();
        }

        public Key privateKey() {
            return privateKey;
        }
    }

    private final Certificate[] certificateChain;
    private final Key dummyPrivateKey;
    private final SignFunction signFunction;

    public SmartCardToken(byte[] certificateBytes, SignFunction fn) {
        this(certificateBytes, new DummyPrivateKey().privateKey(), fn);
    }

    public SmartCardToken(byte[] certificateBytes, Key dummyPrivateKey, SignFunction fn) {
        this(new X509Certificate[]{convertBytesToX509Certificate(certificateBytes)}, dummyPrivateKey, fn);
    }

    public SmartCardToken(Certificate[] certificateChain, SignFunction fn) {
        this(certificateChain, new DummyPrivateKey().privateKey(), fn);
    }

    public SmartCardToken(Certificate[] certificateChain, Key dummyPrivateKey, SignFunction fn) {
        this.certificateChain = certificateChain;
        this.dummyPrivateKey = dummyPrivateKey;
        this.signFunction = fn;
    }


    @Override
    public Key key() {
        return this.dummyPrivateKey;
    }

    @Override
    public byte[] signed(byte[] message) throws Exception {
        return this.signFunction.sign(message);
    }

    @Override
    public char[] password() {
        return "".toCharArray(); // dummy password for the dummy key
    }

    private static X509Certificate convertBytesToX509Certificate(byte[] certificateBytes) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes);
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            return certificate;
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Certificate[] certificateChain() {
        return this.certificateChain;
    }

}
