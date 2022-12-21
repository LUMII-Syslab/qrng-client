package org.bouncycastle.pqc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.BCSPHINCSPlusPrivateKey;
import org.bouncycastle.tls.InjectedSigners;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;

/**
 * The class for injecting PQC algorithms used for our experiments (~post-quantum agility)
 *
 * #pqc-tls #injection
 * @author Sergejs Kozlovics
 */
public class InjectablePQC {
    public void inject() {
        InjectedSigners.injectSigner("SPHINCS+", (JcaTlsCrypto crypto, PrivateKey privateKey)->{
            assert (privateKey instanceof BCSPHINCSPlusPrivateKey);

            InjectableSphincsPlusTlsSigner signer = new InjectableSphincsPlusTlsSigner();

            BCSPHINCSPlusPrivateKey k = (BCSPHINCSPlusPrivateKey)privateKey;
            SPHINCSPlusPrivateKeyParameters p = (SPHINCSPlusPrivateKeyParameters)k.getKeyParams();
            signer.init(true, p);
                // was: ((SPHINCSPlusSigner)signer).initForSigning(p);
            return signer;
        });


    }

    /**
     1.3.9999.6.7.1 SPHINCS+ OID from open-quantum-safe;
     ALL oqs SIG code points: https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs-template/oqs-sig-info.md
     */
    public static final ASN1ObjectIdentifier oqs_sphincsshake256128frobust_oid = new ASN1ObjectIdentifier("1.3.9999.6.7").branch("1");
    /*
     * RFC 8446 reserved for private use (0xFE00..0xFFFF)
     */
    // by SK: lookup here: https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs-template/oqs-sig-info.md
    public static final int oqs_sphincsshake256128frobust_signaturescheme_codepoint = 0xfe7a; // by SK

    /* TODO: hash = -1 for SPHINCS+, getSignatureAlgorithm = SignatureScheme.getSignatureAlgorithm(signatureScheme)===[RFC 8998] sm2sig_sm3 return (short)(signatureScheme & 0xFF);
    + problems with initialization, if we use SignatureScheme.getHashAlgorithm and SignatureScheme.getSignatureAlgorithm
    public static final SignatureAndHashAlgorithm oqs_sphincsshake256128frobust_sha256 =
            SignatureAndHashAlgorithm.create(SignatureScheme.getHashAlgorithm(signatureSchemeCodePoint), SignatureScheme.getSignatureAlgorithm(signatureSchemeCodePoint));
    */

    private class InjectableSphincsPlusTlsSigner extends SPHINCSPlusSigner implements TlsSigner {

        @Override
        public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
            return this.generateSignature(hash);
        }

        @Override
        public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException {
            return new MyStreamSigner(algorithm);
        }

        private class MyStreamSigner implements TlsStreamSigner {

            SignatureAndHashAlgorithm algorithm;
            private ByteArrayOutputStream os = new ByteArrayOutputStream();

            public MyStreamSigner(SignatureAndHashAlgorithm algorithm)
            {
                this.algorithm = algorithm;
            }
            @Override
            public OutputStream getOutputStream() throws IOException {
                return os;
            }

            @Override
            public byte[] getSignature() throws IOException {
                return InjectableSphincsPlusTlsSigner.this.generateRawSignature(algorithm, os.toByteArray());
            }
        }
    }


}
