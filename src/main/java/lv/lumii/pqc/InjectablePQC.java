package lv.lumii.pqc;

import lv.lumii.qrng.clienttoken.Token;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.crypto.frodo.*;
import org.bouncycastle.pqc.crypto.sphincsplus.*;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.BCSPHINCSPlusPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.BCSPHINCSPlusPublicKey;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.injection.kems.InjectedKEMs;
import org.bouncycastle.tls.injection.kems.KEM;
import org.bouncycastle.tls.injection.sigalgs.*;
import org.bouncycastle.tls.injection.signaturespi.SignatureSpiFromPublicOrPrivateKeyFactory;
import org.bouncycastle.tls.injection.signaturespi.UniversalSignatureSpi;
import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * The class for injecting PQC algorithms used for our experiments (~post-quantum agility)
 * <p>
 * #pqc-tls #injection
 *
 * @author Sergejs Kozlovics
 */
public class InjectablePQC {

    private static final int RSA_CODE_POINT = 0x804;//0x401;//0x804;//0x401;
    // 0x401
    //0x0804, //2052
    //0x0809, // from: https://www.ietf.org/rfc/rfc8446.html   //2057

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

    public interface ClientTokenFactory {
        Token clientToken();
    }

    public static void inject(InjectedKEMs.InjectionOrder injectionOrder, ClientTokenFactory clientTokenFactory) {
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


        SigAlgAPI api = new SigAlgAPI() {
            @Override
            public boolean isSupportedParameter(AsymmetricKeyParameter someKey) {
                return someKey instanceof SPHINCSPlusPublicKeyParameters ||
                        someKey instanceof SPHINCSPlusPrivateKeyParameters;
            }

            @Override
            public AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo keyInfo) throws IOException {
                byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
                // ^^^ if it were: keyInfo.getEncoded() contains also additional stuff, including OID
                // keyInfo.getPrivateKey().getEncoded() contains also SPHINCS+ parameters (4 bytes, big endian)
                SPHINCSPlusParameters spParams = sphincsPlusParameters;

                return new SPHINCSPlusPrivateKeyParameters(spParams, Arrays.copyOfRange(keyEnc, 0, sphincsPlusSKLength));
                // ^^^ since SPHINCS+ keyEnc (as used by OpenQuantumSafe) contains both private key and public key, we need to keep only the private key encoding
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
                SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(wrapped);
                byte[] keyEnc = info.getPublicKeyData().getBytes();
                //byte[] keyEnc = Arrays.copyOfRange(wrapped, wrapped.length - sphincsPlusPKLength, wrapped.length);
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

            @Override
            public PrivateKey generatePrivate(PrivateKeyInfo keyInfo) throws IOException {
                return new SPHINCSPlusKeyFactorySpi().generatePrivate(keyInfo);
            }

            @Override
            public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo) throws IOException {
                return new SPHINCSPlusKeyFactorySpi().generatePublic(keyInfo);
            }

            @Override
            public byte[] internalEncoding(PublicKey key) {
                BCSPHINCSPlusPublicKey pk = (BCSPHINCSPlusPublicKey) key;

                byte[] b4 = SPHINCSPlusParameters.sha2_128f_simple.getEncoded();

                SPHINCSPlusPublicKeyParameters params = (SPHINCSPlusPublicKeyParameters) pk.getKeyParams();
                byte[] b36 = params.getEncoded();
                return b36;
            }

            @Override
            public byte[] sign(JcaTlsCrypto crypto, byte[] message, byte[] privateKey) throws IOException {
                SPHINCSPlusSigner signer = new SPHINCSPlusSigner();

                privateKey = Arrays.copyOfRange(privateKey, 4, privateKey.length); // skip SPHICS+ parameters, 4 bytes big-endian
                //int sphincsPlusParams = Pack.bigEndianToInt(privateKey, 0);


                signer.init(true, new SPHINCSPlusPrivateKeyParameters(sphincsPlusParameters, privateKey));
                byte[] bcSignature = signer.generateSignature(message);
                return bcSignature;
            }

            @Override
            public boolean verifySignature(byte[] message, byte[] publicKey, DigitallySigned signature) {

                System.out.println("Sphincs+ pubkey:");
                System.out.println(InjectablePQC.byteArrayToString(publicKey, " "));

                publicKey = Arrays.copyOfRange(publicKey, 4, publicKey.length); // skip SPHICS+ parameters, 4 bytes big-endian
                //int sphincsPlusParams = Pack.bigEndianToInt(publicKey, 0);

                // BouncyCastle verifier

                SPHINCSPlusSigner signer = new SPHINCSPlusSigner();

                SPHINCSPlusPublicKeyParameters params = new SPHINCSPlusPublicKeyParameters(
                        sphincsPlusParameters, publicKey);
                signer.init(false, params);
                boolean b = signer.verifySignature(message, signature.getSignature());
                return b;
            }
        };

        InjectedSigAlgorithms.injectSigAndHashAlgorithm(
                "SPHINCS+",//"SPHINCSPLUS",
                sigOid,
                sigCodePoint,
                api,
                (Key publicOrPrivateKey) -> {


                    if ("SPHINCS+".equals(publicOrPrivateKey.getAlgorithm())) {
                        System.out.println("X509 SPHINCS+ pubkey");
                        byte[] b = publicOrPrivateKey.getEncoded();
                        System.out.println(InjectablePQC.byteArrayToString(b, " "));
                        byte[] publicKey = Arrays.copyOfRange(b, b.length - 32, b.length);
                        SPHINCSPlusPublicKeyParameters params = new SPHINCSPlusPublicKeyParameters(
                                sphincsPlusParameters, publicKey);
                        publicOrPrivateKey = new BCSPHINCSPlusPublicKey(params);
                    }

                    if (publicOrPrivateKey instanceof BCSPHINCSPlusPublicKey) {
                        PublicKeyToCipherParameters f1 = (pk) -> {
                            if ("SPHINCS+".equals(pk.getAlgorithm())) {
                                byte[] b = pk.getEncoded();
                                byte[] publicKey = Arrays.copyOfRange(b, b.length - 32, b.length);
                                SPHINCSPlusPublicKeyParameters params = new SPHINCSPlusPublicKeyParameters(
                                        sphincsPlusParameters, publicKey);
                                pk = new BCSPHINCSPlusPublicKey(params);
                            }

                            return ((BCSPHINCSPlusPublicKey) pk).getKeyParams();
                        };
                        PrivateKeyToCipherParameters f2 = (sk) -> ((BCSPHINCSPlusPrivateKey) sk).getKeyParams();

                        return new UniversalSignatureSpi(new NullDigest(),
                                new MyMessageSigner(
                                        sigCodePoint,
                                        (crypto, data, key) -> api.sign(crypto, data, key),
                                        (message, pk, signature) -> api.verifySignature(message, pk, signature),
                                        (params) -> {
                                            assert params instanceof SPHINCSPlusPublicKeyParameters;
                                            SPHINCSPlusPublicKeyParameters pkParams = (SPHINCSPlusPublicKeyParameters) params;
                                            return pkParams.getEncoded();
                                        },
                                        (params) -> {
                                            assert params instanceof SPHINCSPlusPrivateKeyParameters;
                                            SPHINCSPlusPrivateKeyParameters skParams = (SPHINCSPlusPrivateKeyParameters) params;
                                            SPHINCSPlusPublicKeyParameters pkParams = new SPHINCSPlusPublicKeyParameters(skParams.getParameters(), skParams.getPublicKey()); // needed for verifiers
                                            return skParams.getEncoded();
                                        }),
                                f1, f2);
                        //return new SphincsPlusSignatureSpi();
                    } else
                        throw new RuntimeException("Only  SPHINCS+ is supported in this implementation of InjectedSignatureSpi.Factory");
                }
        );

        SigAlgAPI rsa_api = new SigAlgAPI() {
            @Override
            public boolean isSupportedParameter(AsymmetricKeyParameter someKey) {
                System.out.println(someKey.getClass().getName());
                return true;
            }

            @Override
            public AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo keyInfo) throws IOException {
                System.out.println(keyInfo.getClass().getName());
                return null;
            }

            @Override
            public PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes) throws IOException {
                System.out.println(privateKey.getClass().getName());
                return null;

            /*    byte[] encoding = params.getEncoded(); // ££££
                byte[] pubEncoding = params.getEncodedPublicKey();

                // remove alg params (4 bytes)
                encoding = Arrays.copyOfRange(encoding, 4, encoding.length);
                pubEncoding = Arrays.copyOfRange(pubEncoding, 4, pubEncoding.length);

                AlgorithmIdentifier algorithmIdentifier =
                        new AlgorithmIdentifier(sigOid);
                //new AlgorithmIdentifier(Utils.sphincsPlusOidLookup(params.getParameters()));  // by SK: here BC gets its algID!!!  @@@ @@@
                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);*/
            }

            @Override
            public AsymmetricKeyParameter createPublicKeyParameter(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
                byte[] wrapped = keyInfo.getEncoded(); // ASN1 wrapped
                SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(wrapped);
                byte[] keyEnc = info.getPublicKeyData().getBytes();
                //byte[] keyEnc = Arrays.copyOfRange(wrapped, wrapped.length - sphincsPlusPKLength, wrapped.length);
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

            @Override
            public PrivateKey generatePrivate(PrivateKeyInfo keyInfo) throws IOException {
                return new SPHINCSPlusKeyFactorySpi().generatePrivate(keyInfo);
            }

            @Override
            public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo) throws IOException {
                return new SPHINCSPlusKeyFactorySpi().generatePublic(keyInfo);
            }

            @Override
            public byte[] internalEncoding(PublicKey key) {
                return key.getEncoded();
            }

            private byte[] sha256(byte[] data) {
                SHA256Digest digest = new SHA256Digest();

                // Update the digest with your data
                digest.update(data, 0, data.length);

                // Calculate the SHA-256 hash
                byte[] sha256Hash = new byte[digest.getDigestSize()];
                digest.doFinal(sha256Hash, 0);
                return sha256Hash;
            }

            private static byte[] constructPKCS1v15PaddedMessage(byte[] hash, int keySizeBytes) throws Exception {
                //if (hash.length != 32) {
                //  throw new IllegalArgumentException("Hash length must be 32 bytes (256 bits) for SHA-256.");
                //}

                int paddingSize = keySizeBytes - hash.length - 3;
                if (paddingSize < 8) {
                    throw new IllegalArgumentException("Key size is too small for PKCS#1 v1.5 padding.");
                }

                byte[] paddedMessage = new byte[keySizeBytes];
                paddedMessage[0] = 0x00;
                paddedMessage[1] = 0x01; // Block type 01

                // Add padding bytes (random non-zero values)
                byte[] padding = new byte[paddingSize];
                for (int i = 0; i < paddingSize; i++) {
                    padding[i] = (byte) 0xFF; // Use 0xFF for simplicity, but it's typically random non-zero bytes
                }

                // Copy the hash at the end of the padded message
                System.arraycopy(padding, 0, paddedMessage, 2, paddingSize);
                paddedMessage[paddingSize + 2] = 0x00; // Separator
                System.arraycopy(hash, 0, paddedMessage, paddingSize + 3, hash.length);

                return paddedMessage;
            }

            private static byte[] combineOIDAndHash(ASN1ObjectIdentifier oid, byte[] hash) throws IOException {
                ASN1EncodableVector vector = new ASN1EncodableVector();


                ASN1EncodableVector vector2 = new ASN1EncodableVector();
                vector2.add(oid);
                vector2.add(DERNull.INSTANCE);

                vector.add(new DERSequence(vector2));

                // Add the hash value to the vector as an ASN1OctetString
                DEROctetString octetString = new DEROctetString(hash);

                vector.add(octetString);

                // Create an ASN1Sequence from the vector
                ASN1Sequence sequence = new DERSequence(vector);

                // Print the ASN1Sequence (encoded as bytes)
                byte[] encodedSequence = sequence.getEncoded();
                return encodedSequence;
            }

            @Override
            public byte[] sign(JcaTlsCrypto crypto, byte[] message, byte[] privateKey) throws Exception {
                System.out.println("message length  " + message.length);
                System.out.println("SIGNING WITH CARD...");

                try {
                    return clientTokenFactory.clientToken().signed(message);
                } catch (UnsupportedOperationException e) {
                    // If this is a real private key, not dummy, we try to sign by ourselves below.
                }


                ASN1OctetString octetString = ASN1OctetString.getInstance(privateKey);
                ASN1Sequence seq = ASN1Sequence.getInstance(octetString.getOctets());
                ASN1Integer modulus = (ASN1Integer) seq.getObjectAt(1).toASN1Primitive();
                ASN1Integer privateExponent = (ASN1Integer) seq.getObjectAt(3).toASN1Primitive();

                RSAKeyParameters rsaSk = new RSAKeyParameters(true, modulus.getValue(), privateExponent.getValue());


                Digest digest = new SHA256Digest();


                PSSSigner pssSigner = new PSSSigner(new RSAEngine(), digest, 32); // OURS TLS
                pssSigner.init(true, new ParametersWithRandom(rsaSk, crypto.getSecureRandom()));

                // Update the signer with the data to be signed
                pssSigner.update(message, 0, message.length);
                byte[] pssSignatureBytes = pssSigner.generateSignature();
                return pssSignatureBytes;


            }

            @Override
            public boolean verifySignature(byte[] message, byte[] publicKey, DigitallySigned signature) {


                System.out.println("RSA PUB KEY");
                System.out.println(byteArrayToString(publicKey, " "));

                ASN1Sequence seq = ASN1Sequence.getInstance(publicKey);

                ASN1BitString bitStr = (ASN1BitString) seq.getObjectAt(1);
                ASN1Sequence seq2 = ASN1Sequence.getInstance(bitStr.getOctets());

                ASN1Integer modulus = (ASN1Integer) seq2.getObjectAt(0).toASN1Primitive();
                ASN1Integer publicExponent = (ASN1Integer) seq2.getObjectAt(1).toASN1Primitive();

                RSAKeyParameters rsaPk = new RSAKeyParameters(false, modulus.getValue(), publicExponent.getValue());

                Digest digest = new SHA256Digest();

                /*
                Signature signer;
                try {
                    signer = Signature.getInstance("SHA256withRSA");
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                signer.initSign(RSAPrivateKey.getInstance(seq));*/


                //PSSSigner signer = new PSSSigner(new RSAEngine(), digest, 32); // OURS TLS
                RSADigestSigner signer = new RSADigestSigner(digest); // ER SC OR FILE-BASED RSA CERT

                signer.init(false, rsaPk);

                // Update the signer with the data to be signed
                signer.update(message, 0, message.length);

                boolean b = signer.verifySignature(signature.getSignature());
                return b;
            }
        };

        SignatureSpiFromPublicOrPrivateKeyFactory rsa_factory = (Key key) -> {
            System.out.println("RSA KEY GIVEN  (RSA SERVER)  " + key.getClass().getName());

            if (!(key instanceof RSAPublicKey || key instanceof RSAPrivateCrtKey)) {
                throw new RuntimeException("Only RSA is supported in this implementation of InjectedSignatureSpi.Factory");

            }

            //return new PSSSignatureSpi.SHA256withRSA();
            PublicKeyToCipherParameters f1 = (pk) -> {
                RSAPublicKey rsaPk = (RSAPublicKey) pk;

                // converting built-in AlgorithmParameterSpec to CipherParameters
                return new RSAKeyParameters(false, rsaPk.getModulus(), rsaPk.getPublicExponent());
            };
            PrivateKeyToCipherParameters f2 = (sk) -> {
                RSAPrivateCrtKey rsaSk = (RSAPrivateCrtKey) sk;

                // converting built-in AlgorithmParameterSpec to CipherParameters
                return new RSAKeyParameters(true, rsaSk.getModulus(), rsaSk.getPrivateExponent());
            };

            //return new  PSSSignatureSpi.SHA256withRSA();


            return new UniversalSignatureSpi(new NullDigest(),
                    new MyMessageSigner(
                            RSA_CODE_POINT,
                            (crypto, data, key1) -> rsa_api.sign(crypto, data, key1),
                            (message, pk, signature) -> rsa_api.verifySignature(message, pk, signature),
                            (params) -> {
                                assert params instanceof RSAKeyParameters;
                                RSAKeyParameters pkParams = (RSAKeyParameters) params;

                                RSAPublicKeyStructure rsaPublicKey = new RSAPublicKeyStructure(
                                        pkParams.getModulus(),
                                        pkParams.getExponent()
                                );

                                // Create an AlgorithmIdentifier for RSA
                                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                                        new ASN1ObjectIdentifier("1.2.840.113549.1.1.1")
                                        //,
                                        //DERNull.INSTANCE // needed for legacy RSA non-PSS, see https://crypto.stackexchange.com/questions/67101/how-to-identify-rsassa-pss-from-rsaencryption-oid
                                );

                                // Create a SubjectPublicKeyInfo
                                try {
                                    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
                                            algorithmIdentifier,
                                            rsaPublicKey.toASN1Primitive()
                                    );

                                    byte[] b = subjectPublicKeyInfo.getEncoded();

                                        /*ASN1EncodableVector seq0 = new ASN1EncodableVector(2);

                                        ASN1EncodableVector v = new ASN1EncodableVector(2);
                                        v.add(algorithmIdentifier);
                                        v.add(DERNull.INSTANCE);
                                        seq0.add(new DERSequence(v));

                                        ASN1BitString bitString = (ASN1BitString) ASN1BitString.fromByteArray(rsaPublicKey.toASN1Primitive().getEncoded());
                                        seq0.add(bitString);

                                        DERSequence generated = new DERSequence(seq0);
                                        byte[] b = generated.getEncoded();

                                        System.out.println("generated pubkey encoding1:");*/
                                    System.out.println(InjectablePQC.byteArrayToString(b, " "));
                                    return b;
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    throw new RuntimeException(e);
                                }
                            },
                            (params) -> {
                                assert params instanceof RSAKeyParameters;
                                RSAKeyParameters skParams = (RSAKeyParameters) params;
                                //return pkParams.getEncoded();
                                return new byte[]{}; // TODO: CipherParameters as wrapper
                            }),
                    f1, f2);

        };

        ASN1ObjectIdentifier rsa_oid1 = new org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WITHRSA").getAlgorithm();
        System.out.println("RSA OID1  : " + rsa_oid1);
//        ASN1ObjectIdentifier rsa_oid2 = new ASN1ObjectIdentifier("1.2.840.113549.1.1.8");
        //      System.out.println("RSA OID2: "+rsa_oid2);

        // needed for verification of the server certificate

        InjectedSigAlgorithms.injectSigAndHashAlgorithm(
                "SHA256WITHRSA",
                //"SHA256WITHRSAANDMGF1", //"RSA",
                rsa_oid1,
                RSA_CODE_POINT,
                rsa_api,
                rsa_factory
        );


        InjectedSigAlgorithms.injectSigAndHashAlgorithm(
                "RSA", //"RSA",
                rsa_oid1,
                RSA_CODE_POINT,

                rsa_api,
                rsa_factory
        );

        /*
        InjectedSigners.injectSigner("SPHINCS+", (JcaTlsCrypto crypto, PrivateKey privateKey) -> {
            assert (privateKey instanceof BCSPHINCSPlusPrivateKey);

            BCSPHINCSPlusPrivateKey sk = (BCSPHINCSPlusPrivateKey) privateKey;
            InjectableSphincsPlusTlsSigner signer = new InjectableSphincsPlusTlsSigner();

            SPHINCSPlusPrivateKeyParameters p = (SPHINCSPlusPrivateKeyParameters) sk.getKeyParams();
* TODO: make this function look like the next one (e.g., VerifySignatureFunction)
            byte[] keys = p.getEncoded(); // TODO: read sphincsPlusParameters from the first 4 big-endian bytes
            SPHINCSPlusPrivateKeyParameters newP = new SPHINCSPlusPrivateKeyParameters(sphincsPlusParameters,
                    Arrays.copyOfRange(keys, 4, keys.length));
            p = newP;*
            signer.init(true, p);

            return signer;
        });
        InjectedSigVerifiers.injectVerifier(
                sigCodePoint,
                (InjectedSigVerifiers.VerifySignatureFunction) (data, key, signature) -> {
                    // BouncyCastle verifier
                    int from = 26; // see der.md
                    int priorTo = key.length;
                    SPHINCSPlusSigner signer = new SPHINCSPlusSigner();

                    byte[] pubKey = Arrays.copyOfRange(key, from, priorTo);
                    SPHINCSPlusPublicKeyParameters params = new SPHINCSPlusPublicKeyParameters(
                            sphincsPlusParameters, pubKey);
                    signer.init(false, params);
                    boolean b = signer.verifySignature(data, signature.getSignature());
                    return b;
                });*/

        //InjectedKEMs.injectKEM(oqs_frodo640aes_codepoint, "FrodoKEM-640-AES",
        //      (crypto, isServer) -> new KemAgreement(crypto, isServer, new InjectableFrodoKEM()));
        InjectedKEMs.injectKEM(oqs_frodo640aes_codepoint, "FrodoKEM-640-AES",
                () -> new InjectableFrodoKEM());

        BouncyCastleJsseProvider jsseProvider = new BouncyCastleJsseProvider();
        Security.insertProviderAt(jsseProvider, 1);

        BouncyCastlePQCProvider bcProvider = new BouncyCastlePQCProvider(); // BCPQC
        Security.insertProviderAt(bcProvider, 1);
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
        s = s.replaceAll(" ", ""); // remove all spaces
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


    }

}
