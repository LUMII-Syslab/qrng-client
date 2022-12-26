package org.bouncycastle.pqc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.frodo.*;
import org.bouncycastle.tls.crypto.*;
import org.bouncycastle.tls.crypto.impl.jcajce.JceTlsSecret;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;
import org.bouncycastle.pqc.crypto.util.Utils;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.BCSPHINCSPlusPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * The class for injecting PQC algorithms used for our experiments (~post-quantum agility)
 * <p>
 * #pqc-tls #injection
 *
 * @author Sergejs Kozlovics
 */
public class InjectablePQC {

    // KEM code points
    /*
    ??? RFC 4492 reserved ecdhe_private_use (0xFE00..0xFEFF)

    ALL oqs KEM code points: https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs-template/oqs-kem-info.md
     */
    private static final int oqs_frodo640shake_codepoint = 0x0201;

    // Signature Scheme code points and OIDs
    /*
     * 1.3.9999.6.7.1 SPHINCS+ OID from open-quantum-safe;
     * ALL oqs SIG code points: https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs-template/oqs-sig-info.md
     */
    public static final ASN1ObjectIdentifier oqs_sphincsshake256128frobust_oid = new ASN1ObjectIdentifier("1.3.9999.6.7").branch("1");
    /*
     * RFC 8446 reserved for private use (0xFE00..0xFFFF)
     */
    // by SK: lookup here: https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs-template/oqs-sig-info.md
    public static final int oqs_sphincsshake256128frobust_signaturescheme_codepoint = 0xfe7a; // by SK

    public static void inject() {
        // PQC signatures are huge; increasing the max handshake size:
        System.setProperty("jdk.tls.maxHandshakeMessageSize", String.valueOf(32768 * 32));
        //System.setProperty("jdk.tls.client.SignatureSchemes", "SPHINCS+"); // comma-separated


        InjectedSigAlgorithms.injectSigAndHashAlgorithm(
                "SPHINCS+",//"SPHINCSPLUS",
                oqs_sphincsshake256128frobust_oid,
                new SignatureAndHashAlgorithm((short)(oqs_sphincsshake256128frobust_signaturescheme_codepoint>>8),(short)(oqs_sphincsshake256128frobust_signaturescheme_codepoint & 0xFF)),
                oqs_sphincsshake256128frobust_signaturescheme_codepoint,
                (short)(oqs_sphincsshake256128frobust_signaturescheme_codepoint>>8),
                new InjectedConverter() {
                    @Override
                    public boolean isSupportedParameter(AsymmetricKeyParameter someKey) {
                        return someKey instanceof SPHINCSPlusPublicKeyParameters ||
                                someKey instanceof SPHINCSPlusPrivateKeyParameters;
                    }

                    @Override
                    public AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo keyInfo) throws IOException {
                        byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
                        int i = Integers.valueOf(Pack.bigEndianToInt(keyEnc, 0));
                        SPHINCSPlusParameters spParams = SPHINCSPlusParameters.shake_128f;//.getParams(Integers.valueOf(Pack.bigEndianToInt(keyEnc, 0)));
                        return new SPHINCSPlusPrivateKeyParameters(spParams, Arrays.copyOfRange(keyEnc, 0, 64)); // 32 bytes pub key; 32+32 bytes priv key (2 copies)
                    }

                    @Override
                    public PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes) throws IOException {
                        SPHINCSPlusPrivateKeyParameters params = (SPHINCSPlusPrivateKeyParameters) privateKey;

                        byte[] encoding = params.getEncoded();
                        byte[] pubEncoding = params.getEncodedPublicKey();

                        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.sphincsPlusOidLookup(params.getParameters()));
                        return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
                    }

                    @Override
                    public AsymmetricKeyParameter createPublicKeyParameter(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
                        //byte[] keyEnc = keyInfo.getEncoded(); //.octets();
                        byte[] wrapped = keyInfo.getEncoded(); // ASN1 wrapped
                        byte[] keyEnc = Arrays.copyOfRange(wrapped, wrapped.length-32, wrapped.length) ; // ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();
                        AlgorithmIdentifier alg = keyInfo.getAlgorithm();
                        byte[] b = alg.getEncoded();
                        int i = (0x020101); // see file SPHINCSPlusParameters.java // by SK3
                        SPHINCSPlusParameters spParams = SPHINCSPlusParameters.getParams(i);
                        return new SPHINCSPlusPublicKeyParameters(spParams, keyEnc);
                    }

                    @Override
                    public SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) throws IOException {
                        SPHINCSPlusPublicKeyParameters params = (SPHINCSPlusPublicKeyParameters) publicKey;

                        byte[] encoding = params.getEncoded();

                        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.sphincsPlusOidLookup(params.getParameters())); // by SK: here BC gets its algID!!!
                        return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
                    }
                },
                new SPHINCSPlusKeyFactorySpi()
        );
        InjectedSigners.injectSigner("SPHINCS+", (JcaTlsCrypto crypto, PrivateKey privateKey) -> {
            assert (privateKey instanceof BCSPHINCSPlusPrivateKey);

            InjectableSphincsPlusTlsSigner signer = new InjectableSphincsPlusTlsSigner();

            BCSPHINCSPlusPrivateKey k = (BCSPHINCSPlusPrivateKey) privateKey;
            SPHINCSPlusPrivateKeyParameters p = (SPHINCSPlusPrivateKeyParameters) k.getKeyParams();
            signer.init(true, p);
            // was: ((SPHINCSPlusSigner)signer).initForSigning(p);
            return signer;
        });
        InjectedSigVerifiers.injectVerifier(
                oqs_sphincsshake256128frobust_signaturescheme_codepoint,
                (InjectedSigVerifiers.VerifySignatureFunction) (data, key, signature) -> {
                    int from = 26; // see der.md
                    int priorTo = key.length;
                    SPHINCSPlusSigner signer = new SPHINCSPlusSigner();
                    byte[] pubKey = Arrays.copyOfRange(key, from, priorTo);
                    SPHINCSPlusPublicKeyParameters params = new SPHINCSPlusPublicKeyParameters(
                            SPHINCSPlusParameters.shake_128f, pubKey);
                    signer.init(false, params);
                    boolean b = signer.verifySignature(data, signature.getSignature());
                    return b;
                });

        InjectedKEMs.injectKEM(oqs_frodo640shake_codepoint, "FrodoKEM-640-AES",
                (crypto, kemCodePoint) -> new InjectableFrodoKEMAgreement(crypto, "FrodoKEM-640-AES"));

        BouncyCastleJsseProvider jsseProvider = new BouncyCastleJsseProvider();
        Security.insertProviderAt(jsseProvider, 1);

        BouncyCastlePQCProvider bcProvider = new BouncyCastlePQCProvider(); // BCPQC
        Security.insertProviderAt(bcProvider, 1);
    }



    private static class InjectableSphincsPlusTlsSigner extends SPHINCSPlusSigner implements TlsSigner {


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

            public MyStreamSigner(SignatureAndHashAlgorithm algorithm) {
                this.algorithm = algorithm;
            }

            @Override
            public OutputStream getOutputStream() throws IOException {
                return os;
            }

            @Override
            public byte[] getSignature() throws IOException {
                //return InjectableSphincsPlusTlsSigner.this.generateRawSignature(algorithm, os.toByteArray());

                byte[] data = os.toByteArray();
                byte[] signature = InjectableSphincsPlusTlsSigner.this.generateRawSignature(algorithm, data);
                return signature;
            }
        }
    }

    public static class InjectableFrodoKEMAgreement implements TlsAgreement // all by SK
    {
        // from the client point of view
        private JcaTlsCrypto crypto;
        // private org.openquantumsafe.KeyEncapsulation kem; - if via liboqs + JNI + DLL

        FrodoKeyPairGenerator kemGen;
        private byte[] clientPublicKey = null;
        private byte[] clientPrivateKey = null;
        private byte[] serverEnsapsulated = null;

        public InjectableFrodoKEMAgreement(JcaTlsCrypto crypto, String kemName) {
            this.crypto = crypto;
            // this.kem = new KeyEncapsulation(kemName); - if via liboqs + JNI + DLL
            this.kemGen = new FrodoKeyPairGenerator();
            this.kemGen.init(new FrodoKeyGenerationParameters(new SecureRandom(), FrodoParameters.frodokem640shake));
        }

        public byte[] generateEphemeral() throws IOException {
            // if via liboqs JNI + DLL:
            //this.clientPublicKey = kem.generate_keypair();
            //this.clientPrivateKey = kem.export_secret_key().clone();

            // if pure Java (BouncyCastle):
            AsymmetricCipherKeyPair kp = kemGen.generateKeyPair();
            FrodoPublicKeyParameters pubParams = (FrodoPublicKeyParameters) (kp.getPublic());
            FrodoPrivateKeyParameters privParams = (FrodoPrivateKeyParameters) (kp.getPrivate());
            this.clientPublicKey = pubParams.publicKey.clone();
            this.clientPrivateKey = privParams.getPrivateKey().clone();

            return this.clientPublicKey;

        }

        public void receivePeerValue(byte[] peerValue) throws IOException {
            this.serverEnsapsulated = peerValue;
        }

        public TlsSecret calculateSecret() throws IOException {
            // if via liboqs JNI + DLL:
            //byte[] shared_secret_client = kem.decap_secret(this.serverEnsapsulated);
            //this.kem.dispose_KEM();
            //return new JceTlsSecret(this.crypto, shared_secret_client);


            // if pure Java (BouncyCastle):
            FrodoPrivateKeyParameters priv = new FrodoPrivateKeyParameters(FrodoParameters.frodokem640shake, this.clientPrivateKey);
            FrodoKEMExtractor ext = new FrodoKEMExtractor(priv);

            byte[] shared_secret_client2 = ext.extractSecret(this.serverEnsapsulated);

            return new JceTlsSecret(this.crypto, shared_secret_client2);

        }
    }


}
