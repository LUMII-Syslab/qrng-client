package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.util.Arrays;
//import org.openquantumsafe.Common;
//import org.openquantumsafe.Signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;


public class PQC_CERT_Verifier
    implements TlsVerifier
{
    private final JcaTlsCrypto crypto;
    private final PublicKey publicKey;
    private final int signatureScheme;

    public PQC_CERT_Verifier(JcaTlsCrypto crypto, PublicKey publicKey, int signatureScheme)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == publicKey)
        {
            throw new NullPointerException("publicKey");
        }
        if (!SignatureScheme.isPQC(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.crypto = crypto;
        this.publicKey = publicKey;
        this.signatureScheme = signatureScheme;
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
        /*Signature verifier = new Signature("Rainbow-I-Classic");

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


            /* if liboqs +JNI+DLL is used:
            if (this.signatureScheme==SignatureScheme.oqs_rainbowIclassic) {
                from = 24;
                Signature verifier = new Signature("Rainbow-I-Classic");
                key = Arrays.copyOfRange(key, from, priorTo);

                boolean b = verifier.verify(data, signature.getSignature(), key);
                verifier.dispose_sig();
                return b;
            }
            else*/
            if (this.signatureScheme==SignatureScheme.oqs_sphincsshake256128frobust) {
                from = 26; // see der.md

                SPHINCSPlusSigner signer = new SPHINCSPlusSigner();
                byte[] pubKey = Arrays.copyOfRange(key, from, priorTo);
                SPHINCSPlusPublicKeyParameters params = new SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters.shake256_128f, pubKey);
                signer.init(false, params);
                boolean b = signer.verifySignature(data, signature.getSignature());
                return b;
            }
            else
                throw new RuntimeException("SK: cannot verify unknown signature scheme "+this.signatureScheme);

        }
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException
    {
        return new MyStreamVerifier(this.publicKey, signature, this.signatureScheme);
       /* SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
        String digestName = crypto.getDigestName(cryptoHashAlgorithm);
        String sigName = RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1";

        // NOTE: We explicitly set them even though they should be the defaults, because providers vary
        AlgorithmParameterSpec pssSpec = RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, digestName,
            crypto.getHelper());

        return crypto.createStreamVerifier(sigName, pssSpec, signature.getSignature(), publicKey);*/
        //return null;
    }
}
