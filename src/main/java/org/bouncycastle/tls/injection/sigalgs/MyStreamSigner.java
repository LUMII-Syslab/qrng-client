package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.tls.crypto.TlsStreamSigner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class MyStreamSigner implements TlsStreamSigner {


    private SignerFunction fn;
    private byte[] key;
    private ByteArrayOutputStream os = new ByteArrayOutputStream();

    public MyStreamSigner(byte[] key, SignerFunction fn) {
        this.fn = fn;
        this.key = key;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return os;
    }

    @Override
    public byte[] getSignature() throws IOException {
        byte[] data = os.toByteArray();
        byte[] signature = new byte[0];
        try {
            signature = fn.sign(data, key);
        } catch (Exception e) {
            throw new IOException(e);
        }
        return signature;
    }
}