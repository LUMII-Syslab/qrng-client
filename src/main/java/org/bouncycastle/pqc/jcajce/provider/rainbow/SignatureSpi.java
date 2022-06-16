package org.bouncycastle.pqc.jcajce.provider.rainbow;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.rainbow.RainbowSigner;
// import org.openquantumsafe.Signature; - if liboqs + JNI + DLL are used

/**
 * Rainbow Signature class, extending the jce SignatureSpi.
 */
public class SignatureSpi
        extends java.security.SignatureSpi {
    private Digest digest;
    private RainbowSigner signer;
    private SecureRandom random;
    //private Signature verifier = null; // by SK - if liboqs + JNI + DLL
    //byte[] publicKeyBytes = null; // by SK - if liboqs + JNI + DLL
    ArrayList<Byte> message = new ArrayList<Byte>();

    protected SignatureSpi(Digest digest, RainbowSigner signer) {
        this.digest = digest;
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException {
        /*
        verifier = new Signature("Rainbow-I-Classic"); // by SK - if liboqs + JNI + DLL

        try {
            byte[] arr = publicKey.getEncoded();//publicKey.getEncodedInternal(); // by SK
            this.publicKeyBytes = Arrays.copyOfRange(arr, 24, arr.length);
        }
        catch(Exception e){
            throw new InvalidKeyException("SK verify exception", e);
        }

        digest.reset();
         */

        CipherParameters param;
        param = RainbowKeysToParams.generatePublicKeyParameter(publicKey);

        digest.reset();
        signer.init(false, param);

    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException {
        this.random = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException {
        CipherParameters param;
        param = RainbowKeysToParams.generatePrivateKeyParameter(privateKey);

        if (random != null) {
            param = new ParametersWithRandom(param, random);
        }

        message.clear();
        digest.reset();
        signer.init(true, param);

    }

    protected void engineUpdate(byte b)
            throws SignatureException {
        message.add(b);
        digest.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException {
        for (int i = 0; i < len; i++)
            message.add(b[i + off]);
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
            throws SignatureException {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        try {
            byte[] sig = signer.generateSignature(hash);

            return sig;
        } catch (Exception e) {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
            throws SignatureException {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return signer.verifySignature(hash, sigBytes);

        /* by SK - if liboqs + JNI + DLL:
        byte[] msg = new byte[message.size()];
        for (int i=0; i<msg.length; i++)
            msg[i] = message.get(i);
        boolean b = verifier.verify(msg, sigBytes, this.publicKeyBytes);
        return b;*/
    }

    protected void engineSetParameter(AlgorithmParameterSpec params) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec)
     */
    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }


    static public class withSha224
            extends SignatureSpi {
        public withSha224() {
            super(new SHA224Digest(), new RainbowSigner());
        }
    }

    static public class withSha256
            extends SignatureSpi {
        public withSha256() {
            super(new SHA256Digest(), new RainbowSigner());
        }
    }

    static public class withSha384
            extends SignatureSpi {
        public withSha384() {
            super(new SHA384Digest(), new RainbowSigner());
        }
    }

    static public class withSha512
            extends SignatureSpi {
        public withSha512() {
            super(new SHA512Digest(), new RainbowSigner());
        }
    }
}
