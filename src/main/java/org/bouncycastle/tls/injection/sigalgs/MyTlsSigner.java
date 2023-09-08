package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

import java.io.IOException;

public class MyTlsSigner implements TlsSigner
{
    private SignerFunction fn;
    private byte[] key;

    public MyTlsSigner(byte[] key, SignerFunction fn) {
        this.fn = fn;
        this.key = key;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
            throws IOException {
        try {
            return this.fn.sign(hash, key);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException {
        return new MyStreamSigner(key, this.fn);
    }
}