package lv.lumii.pqc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.BCSPHINCSPlusPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.BCSPHINCSPlusPublicKey;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.injection.sigalgs.MyMessageSigner;
import org.bouncycastle.tls.injection.sigalgs.PrivateKeyToCipherParameters;
import org.bouncycastle.tls.injection.sigalgs.PublicKeyToCipherParameters;
import org.bouncycastle.tls.injection.sigalgs.SigAlgAPI;
import org.bouncycastle.tls.injection.signaturespi.UniversalSignatureSpi;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureSpi;
import java.util.Arrays;

public class InjectableSphincsPlus implements SigAlgAPI {
    private final String name;
    private final ASN1ObjectIdentifier oid;
    private final int codePoint;
    private static final SPHINCSPlusParameters sphincsPlusParameters = SPHINCSPlusParameters.sha2_128f_simple;
    private static final int sphincsPlusParametersAsInt = SPHINCSPlusParameters.getID(sphincsPlusParameters);

    int sphincsPlusPKLength = 32;
    private static int sphincsPlusSKLength = 64;
    // ^^^ see: https://github.com/sphincs/sphincsplus

    public InjectableSphincsPlus() {
        this("SPHINCS+",
                new ASN1ObjectIdentifier("1.3.9999.6.4").branch("13"), // oqs_sphincssha2128fsimple_oid
                0xfeb3); // oqs_sphincssha2128fsimple_signaturescheme_codepoint;
    }

    public InjectableSphincsPlus(String name, ASN1ObjectIdentifier oid, int sigCodePoint) {
        this.name = name;
        this.oid = oid;
        this.codePoint = sigCodePoint;
    }

    public String name() {
        return this.name;
    }

    public ASN1ObjectIdentifier oid() {
        return this.oid;
    }

    public int codePoint() {
        return this.codePoint;
    }

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

        if (encoding.length == sphincsPlusSKLength+4)
            encoding = Arrays.copyOfRange(encoding, 4, encoding.length); // this step is not needed in recent BC versions
        if (pubEncoding.length == sphincsPlusPKLength+4)
            pubEncoding = Arrays.copyOfRange(pubEncoding, 4, pubEncoding.length); // this step is not needed in recent BC versions

        AlgorithmIdentifier algorithmIdentifier =
                new AlgorithmIdentifier(oid);
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
        if (encoding.length == sphincsPlusPKLength+4)
            encoding = Arrays.copyOfRange(encoding, 4, encoding.length);

        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(oid);//??? -- does not matter
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

        try {
            Method m = SPHINCSPlusPublicKeyParameters.class.getDeclaredMethod("getKeyParams");
            m.setAccessible(true);
            SPHINCSPlusPublicKeyParameters params = (SPHINCSPlusPublicKeyParameters) m.invoke(pk); // = pk.getKeyParams();

            byte[] b36 = params.getEncoded();
            return b36;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] sign(JcaTlsCrypto crypto, byte[] message, byte[] privateKey) throws IOException {
        SPHINCSPlusSigner signer = new SPHINCSPlusSigner();

        if (privateKey.length == sphincsPlusSKLength+4)
            privateKey = Arrays.copyOfRange(privateKey, 4, privateKey.length); // skip SPHICS+ parameters, 4 bytes big-endian
        //int sphincsPlusParams = Pack.bigEndianToInt(privateKey, 0);


        signer.init(true, new SPHINCSPlusPrivateKeyParameters(sphincsPlusParameters, privateKey));
        byte[] bcSignature = signer.generateSignature(message);
        return bcSignature;
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] publicKey, DigitallySigned signature) {
        if (publicKey.length == sphincsPlusPKLength+4)
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

    @Override
    public SignatureSpi signatureSpi(Key publicOrPrivateKey) {
        if (name.equals(publicOrPrivateKey.getAlgorithm())) {
            byte[] b = publicOrPrivateKey.getEncoded();
            byte[] publicKey = Arrays.copyOfRange(b, b.length - 32, b.length);
            SPHINCSPlusPublicKeyParameters params = new SPHINCSPlusPublicKeyParameters(
                    sphincsPlusParameters, publicKey);
            publicOrPrivateKey = new BCSPHINCSPlusPublicKey(params);
        }

        if (publicOrPrivateKey instanceof BCSPHINCSPlusPublicKey) {
            PublicKeyToCipherParameters f1 = (pk) -> {
                if (name.equals(pk.getAlgorithm())) {
                    byte[] b = pk.getEncoded();
                    byte[] publicKey = Arrays.copyOfRange(b, b.length - 32, b.length);
                    SPHINCSPlusPublicKeyParameters params = new SPHINCSPlusPublicKeyParameters(
                            sphincsPlusParameters, publicKey);
                    pk = new BCSPHINCSPlusPublicKey(params);
                }

                try {
                    Method m = BCSPHINCSPlusPublicKey.class.getDeclaredMethod("getKeyParams");
                    m.setAccessible(true);
                    return (CipherParameters) m.invoke(pk); // = ((BCSPHINCSPlusPublicKey) pk).getKeyParams();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

            };
            PrivateKeyToCipherParameters f2 = (sk) -> {
                try {
                    Method m = BCSPHINCSPlusPrivateKey.class.getDeclaredMethod("getKeyParams");
                    m.setAccessible(true);
                    return (CipherParameters) m.invoke(sk); // = ((BCSPHINCSPlusPrivateKey) sk).getKeyParams();
                }
                catch (Exception e) {
                    throw new RuntimeException(e);
                }
            };

            return new UniversalSignatureSpi(new NullDigest(),
                    new MyMessageSigner(
                            codePoint,
                            this::sign,
                            this::verifySignature,
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

        } else
            throw new RuntimeException("Only " + name + " is supported in this implementation of SignatureSpi");
    }

}
