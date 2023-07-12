package org.bouncycastle.tls.injection.kems;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JceTlsSecret;
import org.openquantumsafe.Pair;

import java.io.IOException;
import java.util.concurrent.ExecutionException;


/**
 * #pqc-tls #injection
 * A more convenient class to work with KEMs in JCA/JCE.
 * @author Sergejs Kozlovics
 */
public abstract class KEMAgreementBase implements TlsAgreement, KEM {
    protected JcaTlsCrypto crypto;
    protected boolean isServer;

    // writable object state (=assignable "coordinates"):
    protected byte[] mySecretKey = null;
    protected byte[] mySecret = null;
    protected byte[] receivedSecret = null;

    public KEMAgreementBase(JcaTlsCrypto crypto, boolean isServer) {
        this.crypto = crypto;
        this.isServer = isServer;
    }


    public boolean isServer() {
        return this.isServer;
    }

    public byte[] publicKey() {
        Pair<byte[],byte[]> p;

        try {
            p = this.keyGen(); // factory method call
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        byte[] pk = p.getLeft();
        byte[] sk = p.getRight();

        this.mySecretKey = sk;
        return pk;
    }

    public byte[] encapsulatedSecret(byte[] partnerPublicKey) {
        Pair<byte[],byte[]> p;

        try {
            p = this.encapsulate(partnerPublicKey); // factory method call
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        this.mySecret = p.getLeft();
        return p.getRight();
    }

    public void decapsulateSecret(byte[] ciphertext) {
        try {
            this.receivedSecret = this.decapsulate(this.mySecretKey, ciphertext); // factory method call
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public TlsSecret ownSecret() {
        return new JceTlsSecret(this.crypto, this.mySecret); // for non-double KEM
    }

    public TlsSecret receivedSecret() {
        return new JceTlsSecret(this.crypto, this.receivedSecret);
    }

    // excluded TlsAgreement functions:

    public byte[] generateEphemeral() throws IOException {
        throw new IOException("This is a KEM, not a TlsAgreement");
    }

    public void receivePeerValue(byte[] peerEncapsulated) throws IOException {
        throw new IOException("This is a KEM, not a TlsAgreement");
    }

    public TlsSecret calculateSecret() throws IOException {
        throw new IOException("This is a KEM, not a TlsAgreement");
    }

    // included KEM functions (factory methods):

    public abstract Pair<byte[], byte[]> keyGen() throws Exception;
    public abstract Pair<byte[], byte[]> encapsulate(byte[] partnerPublicKey) throws Exception;
    public abstract byte[] decapsulate(byte[] secretKey, byte[] ciphertext) throws Exception;
}
