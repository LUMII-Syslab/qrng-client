package org.bouncycastle.pqc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.frodo.*;
import org.bouncycastle.tls.crypto.*;
import org.bouncycastle.tls.crypto.impl.jcajce.JceTlsSecret;
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
    //public static final ASN1ObjectIdentifier oqs_sphincssha256256frobust_oid = new ASN1ObjectIdentifier("1.3.9999.6.6").branch("1");
    //public static final ASN1ObjectIdentifier oqs_sphincssha256128frobust_oid = new ASN1ObjectIdentifier("1.3.9999.6.4").branch("1");

    /*
     * RFC 8446 reserved for private use (0xFE00..0xFFFF)
     */
    // by SK: lookup here: c
    public static final int oqs_sphincsshake256128frobust_signaturescheme_codepoint = 0xfe7a;
    //public static final int oqs_sphincssha256256frobust_signaturescheme_codepoint = 0xfe72;
    //public static final int oqs_sphincssha256128frobust_signaturescheme_codepoint = 0xfe5e;


    public static void main(String[] args) {
        //org.openquantumsafe.KeyEncapsulation kem;
        for (String s : org.openquantumsafe.Sigs.get_enabled_sigs()) {
            System.out.println("SIG "+s);
        }

        //
        //System.out.println("injectabled pqc main");
    }

    private static String OQS_SIG_NAME =
            "SPHINCS+-SHAKE256-128f-robust"
            //"SPHINCS+-SHA256-128f-robust"
            ;
    public static void inject() {
        // PQC signatures are huge; increasing the max handshake size:
        System.setProperty("jdk.tls.maxHandshakeMessageSize", String.valueOf(32768 * 32));
        //System.setProperty("jdk.tls.client.SignatureSchemes", "SPHINCS+"); // comma-separated


        ASN1ObjectIdentifier sigOid = InjectablePQC.oqs_sphincsshake256128frobust_oid;
        //ASN1ObjectIdentifier sigOid = InjectablePQC.oqs_sphincssha256128frobust_oid;
        int sigCodePoint = InjectablePQC.oqs_sphincsshake256128frobust_signaturescheme_codepoint;
        //int sigCodePoint = InjectablePQC.oqs_sphincssha256128frobust_signaturescheme_codepoint;
        short sigCodePointHi = (short)(sigCodePoint >> 8);
        short sigCodePointLo = (short)(sigCodePoint & 0xFF);
        SPHINCSPlusParameters sphincsPlusParameters = SPHINCSPlusParameters.shake_128f;
        //SPHINCSPlusParameters sphincsPlusParameters = SPHINCSPlusParameters.sha2_128f;
        int sphincsPlusParametersAsInt = SPHINCSPlusParameters.getID(sphincsPlusParameters);
        System.out.println("SPHINCS+ params as int = "+sphincsPlusParametersAsInt);
        int sphincsPlusPKLength = 32;
        int sphincsPlusSKLength = 64;
        // ^^^ see: https://github.com/sphincs/sphincsplus

        InjectedSigAlgorithms.injectSigAndHashAlgorithm(
                "SPHINCS+",//"SPHINCSPLUS",
                sigOid,
                new SignatureAndHashAlgorithm(sigCodePointHi,sigCodePointLo), // todo: compute from sigCodePoint
                sigCodePoint,
                sigCodePointHi,//8,//CryptoHashAlgorithm.sha256, //sigCodePointHi, // TODO: remove this param?
                new InjectedConverter() {
                    @Override
                    public boolean isSupportedParameter(AsymmetricKeyParameter someKey) {
                        return someKey instanceof SPHINCSPlusPublicKeyParameters ||
                                someKey instanceof SPHINCSPlusPrivateKeyParameters;
                    }

                    @Override
                    public AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo keyInfo) throws IOException {
                        byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
                        // ^^^ keyInfo.getEncoded() contains also additional stuff, including OID
                        SPHINCSPlusParameters spParams = sphincsPlusParameters;
                        return new SPHINCSPlusPrivateKeyParameters(spParams, Arrays.copyOfRange(keyEnc, 0, sphincsPlusSKLength));
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
                        byte[] wrapped = keyInfo.getEncoded(); // ASN1 wrapped
                        byte[] keyEnc = Arrays.copyOfRange(wrapped, wrapped.length-sphincsPlusPKLength, wrapped.length) ; // ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();
                        AlgorithmIdentifier alg = keyInfo.getAlgorithm();
                        ASN1ObjectIdentifier oid = alg.getAlgorithm();
                        int i = sphincsPlusParametersAsInt; // TODO: get i from associated oid
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

            BCSPHINCSPlusPrivateKey sk = (BCSPHINCSPlusPrivateKey) privateKey;
            InjectableSphincsPlusTlsSigner signer = new InjectableSphincsPlusTlsSigner();

            SPHINCSPlusPrivateKeyParameters p = (SPHINCSPlusPrivateKeyParameters) sk.getKeyParams();

            /*byte[] keys = p.getEncoded(); // TODO: read sphincsPlusParameters from the first 4 big-endian bytes
            SPHINCSPlusPrivateKeyParameters newP = new SPHINCSPlusPrivateKeyParameters(sphincsPlusParameters,
                    Arrays.copyOfRange(keys, 4, keys.length));
            */
            signer.init(true, p);

            return signer;
        });
        InjectedSigVerifiers.injectVerifier(
                sigCodePoint,
                (InjectedSigVerifiers.VerifySignatureFunction) (data, key, signature) -> {
                    int from = 26; // see der.md
                    int priorTo = key.length;
                    SPHINCSPlusSigner signer = new SPHINCSPlusSigner();
                    byte[] pubKey = Arrays.copyOfRange(key, from, priorTo);
                    SPHINCSPlusPublicKeyParameters params = new SPHINCSPlusPublicKeyParameters(
                            sphincsPlusParameters, pubKey);
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



    public static class InjectableSphincsPlusTlsSigner extends SPHINCSPlusSigner implements TlsSigner {

        //BCSPHINCSPlusPrivateKey privateKey = null;
        //public InjectableSphincsPlusTlsSigner() {
          //  super();
        //}

        //public InjectableSphincsPlusTlsSigner(BCSPHINCSPlusPrivateKey privateKey) {
          //  super();
            //this.privateKey = privateKey;
        //}
        private SPHINCSPlusPrivateKeyParameters skParams = null;
        public SPHINCSPlusPublicKeyParameters pkParams = null;

        @Override
        public void init(boolean forSigning, CipherParameters param) {
            super.init(forSigning, param);
            if (param instanceof SPHINCSPlusPrivateKeyParameters) {
                skParams = (SPHINCSPlusPrivateKeyParameters) param;
                pkParams = new SPHINCSPlusPublicKeyParameters(skParams.getParameters(), skParams.getPublicKey()); // needed for verifiers
            }
            else
                pkParams = (SPHINCSPlusPublicKeyParameters)param;
        }
        @Override
        public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException {
            return this.generateSignature(hash);
        }

        @Override
        public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException {
            return new MyStreamSigner(algorithm);
        }


        @Override
        public byte[] generateSignature(byte[] message) {
            // override with oqs implementation
            byte[] sk = skParams.getEncoded();
            int sphincsPlusParams = Pack.bigEndianToInt(sk, 0);
            System.out.println("GENERATING SIG, SPHINCS+ params = "+sphincsPlusParams+" msg len="+message.length);
            sk = Arrays.copyOfRange(sk, 4, sk.length);

            System.out.println("SK (generateSignature):");

            for (byte b : sk) {
                System.out.printf("%02x ", b);
            }

            System.out.println();

            System.out.println("MSG (generateSignature):");
            for (byte b : message) {
                System.out.printf("%02x ", b);
            }
            System.out.println();

            org.openquantumsafe.Signature oqsSigner = new org.openquantumsafe.Signature(
                    OQS_SIG_NAME,
                    sk);

            byte[] oqsSignature = oqsSigner.sign(message);
            System.out.println("COMPUTED SIG: "+oqsSignature.length+" "+Thread.currentThread());
            for (byte b : Arrays.copyOfRange(oqsSignature, 0, 20)) {
                System.out.printf("%02x ", b);
            }
            System.out.println("...");

            byte[] overridden = super.generateSignature(message);
            System.out.println("OVERRIDDEN SIG: "+overridden.length);
            for (byte b : Arrays.copyOfRange(overridden, 0, 20)) {
                System.out.printf("%02x ", b);
            }
            System.out.println("...");

            byte[] pub = this.skParams.getPublicKey();

            SPHINCSPlusSigner verifier = new SPHINCSPlusSigner();
            verifier.init(false, new SPHINCSPlusPublicKeyParameters(skParams.getParameters(), skParams.getPublicKey()));
            System.out.println("COMPUTED VERIFY: "+this.verifySignature3(message, oqsSignature, pub)+" old:"+verifier.verifySignature(message, oqsSignature));
            System.out.println("OVERRIDDEN VERIFY: "+this.verifySignature3(message, overridden, pub)+" old:"+verifier.verifySignature(message, overridden));

            //return oqsSignature;//  return oqsSignature;
            return oqsSignature;
        }

        public boolean verifySignature3(byte[] message, byte[] signature, byte[] publicKey) {
            org.openquantumsafe.Signature oqsVerifier = new org.openquantumsafe.Signature(
                    OQS_SIG_NAME);
            boolean result = oqsVerifier.verify(message, signature, publicKey);
            return result;
        }
        @Override
        public boolean verifySignature(byte[] message, byte[] signature) {

            // override with oqs implementation
            byte[] pk = pkParams.getEncoded();
            int sphincsPlusParams = Pack.bigEndianToInt(pk, 0);
            System.out.println("VERIFYING SIG(len="+signature.length+"), SPHINCS+ params = "+sphincsPlusParams);

            System.out.println("PK: "+pk.length);
            for (byte b : pk) {
                System.out.printf("%02x ", b);
            }
            System.out.println();
            // 4 bytes big endian - params ID
            pk = Arrays.copyOfRange(pk, 4, pk.length);

            org.openquantumsafe.Signature oqsVerifier = new org.openquantumsafe.Signature(
                    OQS_SIG_NAME);
            boolean result = oqsVerifier.verify(message, signature, pk);
            System.out.println("VERIFY RESULT: "+result);
            return result;
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

                byte[] data = os.toByteArray();//Arrays.copyOfRange(os.toByteArray(), 0, os.size());
                byte[] sk = skParams.getEncoded();

                byte[] signature = InjectableSphincsPlusTlsSigner.this.generateSignature(data);

                int sphincsPlusParams = Pack.bigEndianToInt(sk, 0);
                System.out.println("SK (TlsStreamSigner), SPHINCS+ params = "+sphincsPlusParams);

                sk = Arrays.copyOfRange(sk, 4, sk.length);
                for (byte b : sk) {
                    System.out.printf("%02x ", b);
                }

                System.out.println();
                System.out.println("JAVA SIG: "+signature.length);
                for (byte b : Arrays.copyOfRange(signature,0,20)) {
                    System.out.printf("%02x ", b);
                }
                System.out.println("...");

                org.openquantumsafe.Signature oqsSigner = new org.openquantumsafe.Signature(
                        OQS_SIG_NAME,
                        sk);
                byte[] oqsSignature = oqsSigner.sign(data);
                oqsSigner.print_signature();

                System.out.println("MSG (TlsStreamSigner):");
                for (byte b : data) {
                    System.out.printf("%02x ", b);
                }
                System.out.println();

                System.out.println("C SIG: "+oqsSignature.length+" msg len="+data.length+" "+Thread.currentThread());
                for (byte b : Arrays.copyOfRange(oqsSignature, 0, 20)) {
                    System.out.printf("%02x ", b);
                }
                System.out.println("...");

                return signature;//return oqsSignature;
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
