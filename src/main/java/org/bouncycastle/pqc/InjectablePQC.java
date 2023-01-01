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
import org.bouncycastle.pqc.crypto.util.Utils;
import org.bouncycastle.tls.crypto.*;
import org.bouncycastle.tls.crypto.impl.jcajce.JceTlsSecret;
import org.bouncycastle.util.Pack;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;
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



    private static String OQS_SIG_NAME =
            "SPHINCS+-SHAKE256-128f-robust"
            //"SPHINCS+-SHA256-128f-robust"
            ;
    //private static SPHINCSPlusParameters sphincsPlusParameters = SPHINCSPlusParameters.shake256_128f;
    private static SPHINCSPlusParameters sphincsPlusParameters = SPHINCSPlusParameters.shake_128f;
    //private static SPHINCSPlusParameters sphincsPlusParameters = SPHINCSPlusParameters.sha2_128f;
    private static int sphincsPlusParametersAsInt = SPHINCSPlusParameters.getID(sphincsPlusParameters);

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
                        byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets(); // £££
                        // ^^^ if it were: keyInfo.getEncoded() contains also additional stuff, including OID
                        SPHINCSPlusParameters spParams = sphincsPlusParameters;
                        return new SPHINCSPlusPrivateKeyParameters(spParams, Arrays.copyOfRange(keyEnc, 0, sphincsPlusSKLength));
                    }

                    @Override
                    public PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes) throws IOException {
                        SPHINCSPlusPrivateKeyParameters params = (SPHINCSPlusPrivateKeyParameters) privateKey;

                        byte[] encoding = params.getEncoded(); // ££££
                        byte[] pubEncoding = params.getEncodedPublicKey();

                        // remove alg params (4 bytes)
                        encoding = Arrays.copyOfRange(encoding, 4, encoding.length);
                        pubEncoding = Arrays.copyOfRange(pubEncoding, 4, pubEncoding.length);

                        AlgorithmIdentifier algorithmIdentifier =
                                new AlgorithmIdentifier(sigOid);
                                //new AlgorithmIdentifier(Utils.sphincsPlusOidLookup(params.getParameters()));  // by SK: here BC gets its algID!!!  @@@ @@@
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

                        // remove the first 4 bytes (alg. params)
                        encoding = Arrays.copyOfRange(encoding, 4, encoding.length);

                        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(sigOid);//??? -- does not matter
                       // new AlgorithmIdentifier(Utils.sphincsPlusOidLookup(params.getParameters())); // by SK: here BC gets its algID!!!
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

            byte[] keys = p.getEncoded(); // TODO: read sphincsPlusParameters from the first 4 big-endian bytes
            SPHINCSPlusPrivateKeyParameters newP = new SPHINCSPlusPrivateKeyParameters(sphincsPlusParameters,
                    Arrays.copyOfRange(keys, 4, keys.length));
            p = newP;
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

        public static byte[] generateSignature_oqs(byte[] message, byte[] sk) {
            org.openquantumsafe.Signature oqsSigner = new org.openquantumsafe.Signature(
                    OQS_SIG_NAME,
                    sk);

            byte[] oqsSignature = oqsSigner.sign(message);
            return oqsSignature;
        }

        public static byte[] generateSignature_bc(byte[] message, byte[] sk) {
            SPHINCSPlusSigner signer = new SPHINCSPlusSigner();
            signer.init(true, new SPHINCSPlusPrivateKeyParameters(sphincsPlusParameters, sk));
            //signer.initForSigning(new SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters.shake_128f, sk));
            byte[] bcSignature = signer.generateSignature(message);
            return bcSignature;
        }

        public static boolean verifySignature_oqs(byte[] message, byte[] signature, byte[] publicKey) {
            org.openquantumsafe.Signature oqsVerifier = new org.openquantumsafe.Signature(
                    OQS_SIG_NAME);
            boolean result = oqsVerifier.verify(message, signature, publicKey);
            return result;
        }

        public static boolean verifySignature_bc(byte[] message, byte[] signature, byte[] publicKey) {
            SPHINCSPlusSigner verifier = new SPHINCSPlusSigner();
            verifier.init(false, new SPHINCSPlusPublicKeyParameters(sphincsPlusParameters, publicKey));
            boolean result = verifier.verifySignature(message, signature);
            return result;
        }

        @Override
        public byte[] generateSignature(byte[] message) {
            // override with oqs implementation
            byte[] sk = skParams.getEncoded();
            int sphincsPlusParams = Pack.bigEndianToInt(sk, 0);
            sk = Arrays.copyOfRange(sk, 4, sk.length);


            byte[] pk = skParams.getPublicKey();
            byte[] oqsSignature = InjectableSphincsPlusTlsSigner.generateSignature_oqs(message, sk);
            byte[] bcSignature = InjectableSphincsPlusTlsSigner.generateSignature_bc(message, sk);
            System.out.printf("SECRET KEY:\n%s\n", InjectablePQC.byteArrayToString(sk));

            //System.out.printf("OQS SIGNATURE:\n%s\n", InjectablePQC.byteArrayToString(oqsSignature));
            System.out.printf("OQS SIGNATURE VERIFY: oqs:%b bc:%b\n",
                    InjectableSphincsPlusTlsSigner.verifySignature_oqs(message, oqsSignature, pk),
                    InjectableSphincsPlusTlsSigner.verifySignature_bc(message, oqsSignature, pk));
            //System.out.printf("BC SIGNATURE:\n%s\n", InjectablePQC.byteArrayToString(bcSignature));
            System.out.printf("BC SIGNATURE VERIFY: oqs:%b bc:%b\n",
                    InjectableSphincsPlusTlsSigner.verifySignature_oqs(message, bcSignature, pk),
                    InjectableSphincsPlusTlsSigner.verifySignature_bc(message, bcSignature, pk));

            return oqsSignature;
        }


        @Override
        public boolean verifySignature(byte[] message, byte[] signature) {

            // override with oqs implementation
            byte[] pk = pkParams.getEncoded();
            int sphincsPlusParams = Pack.bigEndianToInt(pk, 0);
            // 4 bytes big endian - params ID
            pk = Arrays.copyOfRange(pk, 4, pk.length);

            boolean result = InjectableSphincsPlusTlsSigner.verifySignature_oqs(message, signature, pk);
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

    ///// TESTS /////

    public static String byteArrayToString(byte[] a) {
        return byteArrayToString(a, "");
    }
    public static String byteArrayToString(byte[] a, String delim) {
        String s = "";
        for (byte b : a) {
            if (s.length()>0)
                s += delim;
            s += String.format("%02x", b);
        }
        return s;
    }
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static void main(String args[]) {
        for (String s : org.openquantumsafe.Sigs.get_enabled_sigs()) {
            //System.out.println("SIG "+s);
        }
        String pkStr = "8776619e7fc2ca19b0be40157190208680007c01b855256123e2866ae71ad34616af34d2a08542a6fcd8b9ceab9ea4fa4bf640a5cd866f87aad16a971603e173";
        byte[] sk = hexStringToByteArray(pkStr);
        byte[] pk = Arrays.copyOfRange(sk, sk.length-32, sk.length);
        byte[] message = new byte[] {};// {0, 1, 2};

        System.out.printf("Signing message '%s'...\n", byteArrayToString(message));

        byte[] oqsSignature = InjectableSphincsPlusTlsSigner.generateSignature_oqs(message, sk);
        byte[] bcSignature = InjectableSphincsPlusTlsSigner.generateSignature_bc(message, sk);
        System.out.printf("SECRET KEY:\n%s\n", InjectablePQC.byteArrayToString(sk));

        //System.out.printf("OQS SIGNATURE:\n%s\n", InjectablePQC.byteArrayToString(oqsSignature));
        System.out.printf("OQS SIGNATURE VERIFY: oqs:%b bc:%b\n",
                InjectableSphincsPlusTlsSigner.verifySignature_oqs(message, oqsSignature, pk),
                InjectableSphincsPlusTlsSigner.verifySignature_bc(message, oqsSignature, pk));
        //System.out.printf("BC SIGNATURE:\n%s\n", InjectablePQC.byteArrayToString(bcSignature));
        System.out.printf("BC SIGNATURE VERIFY: oqs:%b bc:%b\n",
                InjectableSphincsPlusTlsSigner.verifySignature_oqs(message, bcSignature, pk),
                InjectableSphincsPlusTlsSigner.verifySignature_bc(message, bcSignature, pk));

    }

}
