package lv.lumii.pqc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.crypto.frodo.*;
import org.bouncycastle.pqc.crypto.sphincsplus.*;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.BCSPHINCSPlusPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.BCSPHINCSPlusPublicKey;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.SignatureSpi;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.injection.kems.InjectedKEMs;
import org.bouncycastle.tls.injection.kems.KEM;
import org.bouncycastle.tls.injection.kems.KemAgreement;
import org.bouncycastle.tls.injection.keys.BC_ASN1_Converter;
import org.bouncycastle.tls.injection.sigalgs.InjectedSigAlgorithms;
import org.bouncycastle.tls.injection.sigalgs.InjectedSigVerifiers;
import org.bouncycastle.tls.injection.sigalgs.InjectedSigners;
import org.bouncycastle.util.Pack;
import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
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
    //private static final int oqs_frodo640shake_codepoint = 0x0201;

    private static final int oqs_frodo640aes_codepoint = 0x0200;

    // Signature Scheme code points and OIDs
    /*
     * 1.3.9999.6.7.1 SPHINCS+ OID from open-quantum-safe;
     * ALL oqs SIG code points: https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs-template/oqs-sig-info.md
     */
    //public static final ASN1ObjectIdentifier oqs_sphincsshake256128frobust_oid = new ASN1ObjectIdentifier("1.3.9999.6.7").branch("1");
    //public static final ASN1ObjectIdentifier oqs_sphincssha256256frobust_oid = new ASN1ObjectIdentifier("1.3.9999.6.6").branch("1");
    //public static final ASN1ObjectIdentifier oqs_sphincssha256128frobust_oid = new ASN1ObjectIdentifier("1.3.9999.6.4").branch("1");
    public static final ASN1ObjectIdentifier oqs_sphincssha2128fsimple_oid = new ASN1ObjectIdentifier("1.3.9999.6.4").branch("13");


    /*
     * RFC 8446 reserved for private use (0xFE00..0xFFFF)
     */
    //public static final int oqs_sphincsshake256128frobust_signaturescheme_codepoint = 0xfe7a;
    // ^^^ when compiling OQS openssl 1.1.1, go to openssl/oqs-template/generate.yml and enable this algorithm!
    //     then invoke: python3 oqs-template/generate.py
    //public static final int oqs_sphincssha256256frobust_signaturescheme_codepoint = 0xfe72;
    //public static final int oqs_sphincssha256128frobust_signaturescheme_codepoint = 0xfe5e;
    public static final int oqs_sphincssha2128fsimple_signaturescheme_codepoint = 0xfeb3;


    private static String OQS_SIG_NAME =
            //"SPHINCS+-SHAKE256-128f-robust"
            //"SPHINCS+-SHA256-128f-robust"
            "SPHINCS+-SHA2-128f-simple";
    //private static SPHINCSPlusParameters sphincsPlusParameters = SPHINCSPlusParameters.shake256_128f;
    //private static SPHINCSPlusParameters sphincsPlusParameters = SPHINCSPlusParameters.shake_128f;
    private static SPHINCSPlusParameters sphincsPlusParameters = SPHINCSPlusParameters.sha2_128f_simple;
    private static int sphincsPlusParametersAsInt = SPHINCSPlusParameters.getID(sphincsPlusParameters);

    public static void inject(InjectedKEMs.InjectionOrder injectionOrder) {
        // PQC signatures are huge; increasing the max handshake size:
        System.setProperty("jdk.tls.maxHandshakeMessageSize", String.valueOf(32768 * 32));
        //System.setProperty("jdk.tls.client.SignatureSchemes", "SPHINCS+"); // comma-separated


        //ASN1ObjectIdentifier sigOid = InjectablePQC.oqs_sphincsshake256128frobust_oid;
        ASN1ObjectIdentifier sigOid = InjectablePQC.oqs_sphincssha2128fsimple_oid;
        int sigCodePoint = InjectablePQC.oqs_sphincssha2128fsimple_signaturescheme_codepoint;
        int sphincsPlusPKLength = 32;
        int sphincsPlusSKLength = 64;
        // ^^^ see: https://github.com/sphincs/sphincsplus

        InjectedKEMs.injectionOrder = injectionOrder;

        InjectedSigAlgorithms.injectSigAndHashAlgorithm(
                "SPHINCS+",//"SPHINCSPLUS",
                sigOid,
                sigCodePoint,
                new BC_ASN1_Converter() {
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
                        byte[] keyEnc = Arrays.copyOfRange(wrapped, wrapped.length - sphincsPlusPKLength, wrapped.length); // ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();
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
                new SPHINCSPlusKeyFactorySpi(),
                (PublicKey pk) -> {
                    if (pk instanceof BCSPHINCSPlusPublicKey)
                        return new SphincsPlusSignatureSpi();
                    else
                        throw new RuntimeException("Only SPHINCS+ is supported in this implementation of InjectedSignatureSpi.Factory");
                }
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
                    //SPHINCSPlusSigner signer = new SPHINCSPlusSigner(); -- otherwise we need to modify SignatureSpi
                    InjectableSphincsPlusTlsSigner signer = new InjectableSphincsPlusTlsSigner();

                    byte[] pubKey = Arrays.copyOfRange(key, from, priorTo);
                    SPHINCSPlusPublicKeyParameters params = new SPHINCSPlusPublicKeyParameters(
                            sphincsPlusParameters, pubKey);
                    signer.init(false, params);
                    boolean b = signer.verifySignature(data, signature.getSignature());
                    return b;
                });

        InjectedKEMs.injectKEM(oqs_frodo640aes_codepoint, "FrodoKEM-640-AES",
                (crypto, kemCodePoint, isServer) -> new KemAgreement(crypto, isServer, new InjectableFrodoKEM()));

        BouncyCastleJsseProvider jsseProvider = new BouncyCastleJsseProvider();
        Security.insertProviderAt(jsseProvider, 1);

        BouncyCastlePQCProvider bcProvider = new BouncyCastlePQCProvider(); // BCPQC
        Security.insertProviderAt(bcProvider, 1);
    }

    public static class SphincsPlusSignatureSpi extends SignatureSpi { // non-private, otherwise, Java reflection doesn't see it
        public SphincsPlusSignatureSpi() {
            super(new NullDigest(), new InjectableSphincsPlusTlsSigner());
        }
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
            } else
                pkParams = (SPHINCSPlusPublicKeyParameters) param;
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
            //byte[] oqsSignature = InjectableSphincsPlusTlsSigner.generateSignature_oqs(message, sk);
            byte[] bcSignature = InjectableSphincsPlusTlsSigner.generateSignature_bc(message, sk);

            //System.out.printf("OQS SIGNATURE VERIFY: oqs:%b bc:%b\n",
            //      InjectableSphincsPlusTlsSigner.verifySignature_oqs(message, oqsSignature, pk),
            //    InjectableSphincsPlusTlsSigner.verifySignature_bc(message, oqsSignature, pk));

            //System.out.printf("BC SIGNATURE VERIFY: oqs bc%b\n",
            //InjectableSphincsPlusTlsSigner.verifySignature_oqs(message, bcSignature, pk),
            //        InjectableSphincsPlusTlsSigner.verifySignature_bc(message, bcSignature, pk));

            return bcSignature;
        }


        @Override
        public boolean verifySignature(byte[] message, byte[] signature) {

            // override with oqs implementation
            byte[] pk = pkParams.getEncoded();
            int sphincsPlusParams = Pack.bigEndianToInt(pk, 0);
            // 4 bytes big endian - params ID
            pk = Arrays.copyOfRange(pk, 4, pk.length);

            //boolean result = InjectableSphincsPlusTlsSigner.verifySignature_oqs(message, signature, pk);
            boolean result = InjectableSphincsPlusTlsSigner.verifySignature_bc(message, signature, pk);
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
                byte[] data = os.toByteArray();
                byte[] signature = InjectableSphincsPlusTlsSigner.this.generateSignature(data);
                return signature;
            }
        }
    }

    public static class InjectableFrodoKEM implements KEM {
        //private org.openquantumsafe.KeyEncapsulation kem;
        // ^^^ if via liboqs + JNI + DLL
        FrodoKeyPairGenerator kemGen; // - if via BC

        public InjectableFrodoKEM() {
            // String kemName = "FrodoKEM-640-AES";
            //this.kem = new org.openquantumsafe.KeyEncapsulation(kemName);
            // ^^^ if via liboqs + JNI + DLL

            this.kemGen = new FrodoKeyPairGenerator();
            this.kemGen.init(new FrodoKeyGenerationParameters(new SecureRandom(), FrodoParameters.frodokem640aes));
        }


        @Override
        public Pair<byte[], byte[]> keyGen() {
            // at the client side:

            // if via liboqs JNI + DLL:
            //byte[] myPublicKey = kem.generate_keypair().clone();
            //byte[] myPrivateKey = kem.export_secret_key().clone();


            // if pure Java (BouncyCastle):
            AsymmetricCipherKeyPair kp = kemGen.generateKeyPair();
            FrodoPublicKeyParameters pubParams = (FrodoPublicKeyParameters) (kp.getPublic());
            FrodoPrivateKeyParameters privParams = (FrodoPrivateKeyParameters) (kp.getPrivate());
            //variant: byte[] encoded = pubParams.getEncoded();
            //variant: byte[] encoded2 = pubParams.getPublicKey();
            byte[] myPublicKey = pubParams.getPublicKey().clone();//publicKey.clone();
            byte[] myPrivateKey = privParams.getPrivateKey().clone();

            return new Pair<>(myPublicKey, myPrivateKey);
        }

        @Override
        public Pair<byte[], byte[]> encapsulate(byte[] partnerPublicKey) {
            // at the server side:
            // if via liboqs JNI + DLL:
            //Pair<byte[], byte[]> pair = kem.encap_secret(partnerPublicKey);
            //byte[] ciphertext = pair.getLeft();
            //byte[] semiSecret = pair.getRight();
            //return new Pair<>(semiSecret, ciphertext);


            FrodoKEMGenerator gen = new FrodoKEMGenerator(new SecureRandom());
            FrodoPublicKeyParameters pub = new FrodoPublicKeyParameters(FrodoParameters.frodokem640aes, partnerPublicKey);

            SecretWithEncapsulation secretWithEncapsulation = gen.generateEncapsulated(pub);

            //this.mySecret = secretWithEncapsulation.getSecret(); -- will be assigned automatically

            return new Pair<>(secretWithEncapsulation.getSecret(), secretWithEncapsulation.getEncapsulation());

        }

        @Override
        public byte[] decapsulate(byte[] secretKey, byte[] ciphertext) {
            // at the client side

            byte[] sharedSecret;

            // assert: this.secretKey == secretKey
            // if via libqs JNI + DLL:
            //sharedSecret = kem.decap_secret(ciphertext);

            // if BC:
            FrodoPrivateKeyParameters priv = new FrodoPrivateKeyParameters(FrodoParameters.frodokem640aes, secretKey);
            FrodoKEMExtractor ext = new FrodoKEMExtractor(priv);
            sharedSecret = ext.extractSecret(ciphertext);

            // if via liboqs JNI + DLL:
            // this.kem.dispose_KEM();

            return sharedSecret;
        }
    }

    ///// TESTS /////

    public static String byteArrayToString(byte[] a) {
        return byteArrayToString(a, "");
    }

    public static String byteArrayToString(byte[] a, String delim) {
        String s = "";
        for (byte b : a) {
            if (s.length() > 0)
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
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static void main(String args[]) {

        /* if pure-Java BC:

        InjectableFrodoKEMAgreement f1 = new InjectableFrodoKEMAgreement(null, "FrodoKEM-640-AES", false);
        InjectableFrodoKEMAgreement f2 = new InjectableFrodoKEMAgreement(null, "FrodoKEM-640-AES", true);
        Pair<byte[],byte[]> p = f1.keyGen();

        Pair<byte[], byte[]> secEnc = f2.encapsulate(p.getLeft()); // p.getLeft === public key;

        System.out.println("SERVER SECRET="+byteArrayToString(secEnc.getLeft()));
        System.out.println("SERVER ENC="+byteArrayToString(Arrays.copyOfRange(secEnc.getRight(), 0, 20))+"...");

        byte[] clientSecret = f1.decapsulate(p.getRight(), secEnc.getRight());
        System.out.println("CLIENT SECRET="+byteArrayToString(clientSecret));
        */

        // if via liboqs JNI + DLL:

        KeyEncapsulation kem1 = new org.openquantumsafe.KeyEncapsulation("FrodoKEM-640-SHAKE");
        KeyEncapsulation kem2 = new org.openquantumsafe.KeyEncapsulation("FrodoKEM-640-SHAKE");

        byte[] pk1 = kem1.generate_keypair();
        byte[] sk1 = kem1.export_secret_key();

        byte[] pk2 = kem2.generate_keypair();
        byte[] sk2 = kem2.export_secret_key();

        // pk1 =>
        // <= pk2

        Pair<byte[], byte[]> pair1 = kem1.encap_secret(pk2);
        byte[] my1 = pair1.getRight();
        byte[] enc1 = pair1.getLeft();

        Pair<byte[], byte[]> pair2 = kem2.encap_secret(pk1);
        byte[] my2 = pair2.getRight();
        byte[] enc2 = pair2.getLeft();

        byte[] d1 = kem1.decap_secret(enc2);
        byte[] d2 = kem2.decap_secret(enc1);

        System.out.println(byteArrayToString(d1));
        System.out.println(byteArrayToString(my1));
        System.out.println(byteArrayToString(d2));
        System.out.println(byteArrayToString(my2));


        for (String s : org.openquantumsafe.Sigs.get_enabled_sigs()) {
            System.out.println("SIG " + s);
        }
        String pkStr = "8776619e7fc2ca19b0be40157190208680007c01b855256123e2866ae71ad34616af34d2a08542a6fcd8b9ceab9ea4fa4bf640a5cd866f87aad16a971603e173";
        byte[] sk = hexStringToByteArray(pkStr);
        byte[] pk = Arrays.copyOfRange(sk, sk.length - 32, sk.length);


        org.openquantumsafe.Signature oqsSigner = new org.openquantumsafe.Signature(
                OQS_SIG_NAME);
        oqsSigner.generate_keypair();
        pk = oqsSigner.export_public_key();
        sk = oqsSigner.export_secret_key();
        System.out.println("OQS KEYPAIR: " + sk.length + " " + pk.length);
        System.out.println("OQS PK " + byteArrayToString(pk));
        System.out.println("OQS SK " + byteArrayToString(sk));


        SPHINCSPlusKeyPairGenerator generator = new SPHINCSPlusKeyPairGenerator();
        SPHINCSPlusKeyGenerationParameters params = new SPHINCSPlusKeyGenerationParameters(new SecureRandom(), InjectablePQC.sphincsPlusParameters);
        generator.init(params);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        SPHINCSPlusPublicKeyParameters _pk = (SPHINCSPlusPublicKeyParameters) keyPair.getPublic();
        SPHINCSPlusPrivateKeyParameters _sk = (SPHINCSPlusPrivateKeyParameters) keyPair.getPrivate();

        //// comment to use LibOQS-generated keys =>
        pk = _pk.getEncoded();
        pk = Arrays.copyOfRange(pk, 4, pk.length);
        sk = _sk.getEncoded();
        sk = Arrays.copyOfRange(sk, 4, sk.length);
        System.out.println("BC5 KEYPAIR: " + sk.length + " " + pk.length);
        System.out.println("BC PK " + byteArrayToString(pk));
        System.out.println("BC SK " + byteArrayToString(sk));
        //// <= comment to use LibOQS-generated keys

        // TODO: compile and test with latest liboqs 0.8.1-dev
        // https://github.com/open-quantum-safe/liboqs/blob/main/RELEASE.md

        byte[] message = new byte[]{};// {0, 1, 2};

        System.out.printf("Signing message '%s'...\n", byteArrayToString(message));

        byte[] oqsSignature = InjectableSphincsPlusTlsSigner.generateSignature_oqs(message, sk);
        byte[] bcSignature = InjectableSphincsPlusTlsSigner.generateSignature_bc(message, sk);

        System.out.printf("OQS SIG:\n%s\n", InjectablePQC.byteArrayToString(oqsSignature).length() + " " + byteArrayToString(Arrays.copyOfRange(oqsSignature, 0, 50)));
        System.out.printf("BC SIG:\n%s\n", InjectablePQC.byteArrayToString(bcSignature).length() + " " + byteArrayToString(Arrays.copyOfRange(bcSignature, 0, 50)));

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
