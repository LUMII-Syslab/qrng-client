package lv.lumii.pqc;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.injection.sigalgs.MyMessageSigner;
import org.bouncycastle.tls.injection.sigalgs.PrivateKeyToCipherParameters;
import org.bouncycastle.tls.injection.sigalgs.PublicKeyToCipherParameters;
import org.bouncycastle.tls.injection.sigalgs.SigAlgAPI;
import org.bouncycastle.tls.injection.signaturespi.UniversalSignatureSpi;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

public class InjectableSmartCardRSA implements SigAlgAPI {

    private static final int RSA_CODE_POINT = 0x804;//0x401;//0x804;//0x401;
    private static final ASN1ObjectIdentifier rsa_oid = new org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WITHRSA").getAlgorithm();
    private final SmartCardSignFunction smartCardSignFunction;

    public InjectableSmartCardRSA(SmartCardSignFunction smartCardSignFunction) {
        this.smartCardSignFunction = smartCardSignFunction;
    }

    public int codePoint() {
        return RSA_CODE_POINT;
    }

    public ASN1ObjectIdentifier oid() {
        return rsa_oid;
    }

    @Override
    public boolean isSupportedParameter(AsymmetricKeyParameter bcKey) {
        throw new UnsupportedOperationException();
    }

    @Override
    public AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo asnPrivateKey) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter bcPrivateKey, ASN1Set attributes) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public AsymmetricKeyParameter createPublicKeyParameter(SubjectPublicKeyInfo ansPublicKey, Object defaultParams) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter bcPublicKey) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo) throws IOException {
        return null;
    }

    @Override
    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo) throws IOException {
        return null;
    }

    @Override
    public byte[] internalEncoding(PublicKey key) {
        return key.getEncoded();
    }

    @Override
    public byte[] sign(JcaTlsCrypto crypto, byte[] message, byte[] privateKey) throws IOException, Exception {
        try {
            return smartCardSignFunction.sign(message);
        } catch (UnsupportedOperationException e) {
            // If this is a real private key, not dummy, we try to sign by ourselves below.
        }
        catch (Exception ignored) {
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
        ASN1Sequence seq = ASN1Sequence.getInstance(publicKey);

        ASN1BitString bitStr = (ASN1BitString) seq.getObjectAt(1);
        ASN1Sequence seq2 = ASN1Sequence.getInstance(bitStr.getOctets());

        ASN1Integer modulus = (ASN1Integer) seq2.getObjectAt(0).toASN1Primitive();
        ASN1Integer publicExponent = (ASN1Integer) seq2.getObjectAt(1).toASN1Primitive();

        RSAKeyParameters rsaPk = new RSAKeyParameters(false, modulus.getValue(), publicExponent.getValue());

        Digest digest = new SHA256Digest();

        RSADigestSigner signer = new RSADigestSigner(digest);

        signer.init(false, rsaPk);

        // Update the signer with the data to be signed
        signer.update(message, 0, message.length);

        boolean b = signer.verifySignature(signature.getSignature());
        return b;
    }

    @Override
    public SignatureSpi signatureSpi(Key key) {
        if (!(key instanceof RSAPublicKey || key instanceof RSAPrivateCrtKey)) {
            throw new RuntimeException("Only RSA is supported in this implementation of SignatureSpi.");

        }

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



        return new UniversalSignatureSpi(new NullDigest(),
                new MyMessageSigner(
                        RSA_CODE_POINT,
                        this::sign,
                        this::verifySignature,
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

    }
}
