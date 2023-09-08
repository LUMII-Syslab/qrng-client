package org.bouncycastle.tls.injection.sigalgs;

public interface SignerFunction {
    byte[] sign(byte[] data, byte[] key) throws Exception;
}
