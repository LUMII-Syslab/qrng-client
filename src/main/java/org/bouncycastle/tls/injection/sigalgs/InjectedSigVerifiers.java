package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * The class provides the ability inject signature verifiers (e.g., for PQC)
 *
 * #pqc-tls #injection
 * @author Sergejs Kozlovics
 */
public class InjectedSigVerifiers // TODO: => Factory
{
    public interface Function {
        // the super-interface for the 2 possible function types:
        // when injecting, choose the most convenient function to implement
    }
    public interface PublicKeyToVerifierFunction extends Function {
        TlsVerifier invoke(JcaTlsCrypto crypto, PublicKey pk, int signatureScheme);
    }

    public interface VerifySignatureFunction extends Function {
        boolean verifySignature(byte[] data, byte[] key, DigitallySigned signature);
    }
    private static Map<Integer, Function> injectedVerifiers = new HashMap<>();
    public static void injectVerifier(int signatureScheme, PublicKeyToVerifierFunction fn) {
        injectedVerifiers.put(signatureScheme, fn);
    }
    public static void injectVerifier(int signatureScheme, VerifySignatureFunction fn) {
        injectedVerifiers.put(signatureScheme, fn);
    }

    public static boolean isSigSchemeSupported(int sigSchemeCodePoint) {
        return injectedVerifiers.containsKey(sigSchemeCodePoint);
    }
    public static TlsVerifier makeVerifier(JcaTlsCrypto crypto, PublicKey publicKey, int sigSchemeCodePoint)
    {
        Function fn = injectedVerifiers.get(sigSchemeCodePoint);
        if (fn instanceof  PublicKeyToVerifierFunction) {
            TlsVerifier verifier = ((PublicKeyToVerifierFunction) fn).invoke(crypto, publicKey, sigSchemeCodePoint);
            return verifier;
        }
        if (fn instanceof VerifySignatureFunction) {
            TlsVerifier verifier = new MyTlsVerifier(crypto, publicKey, sigSchemeCodePoint, (VerifySignatureFunction)fn);
            return verifier;
        }
        throw new RuntimeException("Could not create a signature verifier for the scheme "+sigSchemeCodePoint);
    }

    // implementing TlsVerifier via VerifySignatureFunction
    private static class MyTlsVerifier
            implements TlsVerifier
    {
        private final JcaTlsCrypto crypto;
        private final PublicKey publicKey;
        private final int signatureScheme;
        private final VerifySignatureFunction fn;

        public MyTlsVerifier(JcaTlsCrypto crypto, PublicKey publicKey, int signatureScheme, VerifySignatureFunction fn)
        {
            if (null == crypto)
            {
                throw new NullPointerException("crypto");
            }
            if (null == publicKey)
            {
                throw new NullPointerException("publicKey");
            }
            if (!isSigSchemeSupported(signatureScheme))
            {
                throw new IllegalArgumentException("signatureScheme");
            }

            this.crypto = crypto;
            this.publicKey = publicKey;
            this.signatureScheme = signatureScheme;
            this.fn = fn;
        }

        public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
        {
            throw new UnsupportedOperationException();
        /*Signature verifier = new Signature("Rainbow-I-Classic"); // TODO:

        byte[] key = publicKey.getEncoded();
        key = Arrays.copyOfRange(key, 24, key.length);

        boolean b = verifier.verify(hash, signature.getSignature(), key);
        verifier.dispose_sig();
        return b;*/
        }

        private class MyStreamVerifier implements TlsStreamVerifier {

            private PublicKey publicKey;
            private DigitallySigned signature;
            private ByteArrayOutputStream stream;
            private int signatureScheme;

            public MyStreamVerifier(PublicKey publicKey, DigitallySigned signature, int signatureScheme)
            {
                this.publicKey = publicKey;
                this.signature = signature;
                this.stream = new ByteArrayOutputStream();
                this.signatureScheme = signatureScheme;
            }

            @Override
            public OutputStream getOutputStream() throws IOException {
                return this.stream;
            }

            @Override
            public boolean isVerified() throws IOException {

                byte[] data = this.stream.toByteArray();
                byte[] key = publicKey.getEncoded();

                int from=0;
                int priorTo = key.length;


            /* if liboqs +JNI+DLL is used: // TODO
            if (this.signatureScheme==SignatureScheme.oqs_rainbowIclassic) {
                from = 24;
                Signature verifier = new Signature("Rainbow-I-Classic");
                key = Arrays.copyOfRange(key, from, priorTo);

                boolean b = verifier.verify(data, signature.getSignature(), key);
                verifier.dispose_sig();
                return b;
            }
            else*/
                /* for signatureScheme==SignatureScheme.oqs_sphincsshake256128frobust:
                    from = 26; // see der.md

                    SPHINCSPlusSigner signer = new SPHINCSPlusSigner();
                    byte[] pubKey = Arrays.copyOfRange(key, from, priorTo);
                    SPHINCSPlusPublicKeyParameters params = new SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters.shake256_128f, pubKey);
                    signer.init(false, params);
                    boolean b = signer.verifySignature(data, signature.getSignature());
                    return b;

                 */

                // the main functionality of MyTlsVerifier:
                return fn.verifySignature(data, key, signature);
            }
        }

        public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException
        {
            return new MyStreamVerifier(this.publicKey, signature, this.signatureScheme);

        }
    }

}
