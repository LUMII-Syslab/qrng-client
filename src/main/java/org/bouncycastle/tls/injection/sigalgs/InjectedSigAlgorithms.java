package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.injection.keys.BC_ASN1_Converter;
import org.bouncycastle.tls.injection.signaturespi.DirectSignatureSpi;
import org.bouncycastle.tls.injection.signaturespi.InjectedSignatureSpiFactories;
import org.bouncycastle.tls.injection.signaturespi.SignatureSpiFromPublicKeyFactory;

import java.io.IOException;
import java.util.*;

/**
 * A class representing injected signature algorithms. #pqc-tls #injection
 *
 * @author Sergejs Kozlovics
 */
public class InjectedSigAlgorithms
{
    public static class SigAlgorithmInfo {
        private String name;
        private ASN1ObjectIdentifier oid;
        private int signatureSchemeCodePoint;
        private SignatureAndHashAlgorithm signatureAndHashAlgorithm;
            // ^^^ Just splits the code point (a 2-byte integer) into two separate bytes:
            //     HighestByte(signatureSchemeCodePoint), LowestByte(signatureSchemeCodePoint).
            //     Actually, the highest (the second) byte does not necessarily correspond to the hash algorithm,
            //     but we still use the BC SignatureAndHashAlgorithm class since it is needed internally
            //     in many places within BC code.
        private BC_ASN1_Converter converter;
        private AsymmetricKeyInfoConverter infoToKeyConverter;
        private SignatureSpiFromPublicKeyFactory sig2spiFactory;
        public SigAlgorithmInfo(String name,

                            ASN1ObjectIdentifier oid, // SignatureAndHashAlgorithm sigAndHash,
                            int signatureSchemeCodePoint, // int cryptoHashAlgorithmIndex,
                            BC_ASN1_Converter converter,
                            AsymmetricKeyInfoConverter infoToKeyConverter, SignatureSpiFromPublicKeyFactory sig2spiFactory) {
            this.name = name;
            this.oid = oid;
            this.signatureSchemeCodePoint = signatureSchemeCodePoint;
            this.signatureAndHashAlgorithm = new SignatureAndHashAlgorithm((short) (signatureSchemeCodePoint >> 8), (short) (signatureSchemeCodePoint & 0xFF));
            this.converter = converter;
            this.infoToKeyConverter = infoToKeyConverter;
            this.sig2spiFactory = sig2spiFactory;
        }

        public String name() {
            return this.name;
        }

        public ASN1ObjectIdentifier oid() {
            return this.oid;
        }

        public int signatureSchemeCodePoint() {
            return this.signatureSchemeCodePoint;
        }

        public SignatureAndHashAlgorithm signatureAndHashAlgorithm() {
            return this.signatureAndHashAlgorithm;
        }

    }
    private static final Vector<SigAlgorithmInfo> injected = new Vector<>();
    private static final Map<Integer, SigAlgorithmInfo> injectedSignatureSchemes = new HashMap<>();
    private static final Map<String, SigAlgorithmInfo> injectedOids = new HashMap<>();

    public static void injectSigAndHashAlgorithm(String name,
                                                 ASN1ObjectIdentifier oid,
                                                 int signatureSchemeCodePoint, // e.g., oqs_sphincsshake256128frobust
                                                 BC_ASN1_Converter converter,
                                                 AsymmetricKeyInfoConverter infoToKeyConverter,
                                                 SignatureSpiFromPublicKeyFactory sig2spi) {
        SigAlgorithmInfo newAlg = new SigAlgorithmInfo(name, oid, signatureSchemeCodePoint,
                converter, infoToKeyConverter, sig2spi);
        injected.add(newAlg);
        injectedSignatureSchemes.put(signatureSchemeCodePoint, newAlg);
        injectedOids.put(oid.toString(), newAlg);
        InjectedSignatureSpiFactories.registerFactory(sig2spi);
    }

    public static Collection<? extends SignatureAndHashAlgorithm> getInjectedSigAndHashAlgorithms() {
        return injected.stream().map(info->info.signatureAndHashAlgorithm()).toList();
    }

    public static Collection<? extends SigAlgorithmInfo> getInjectedSigAndHashAlgorithmsInfos() {
        return injected;
    }

    public static boolean isSigSchemeSupported(int sigSchemeCodePoint) {
        return injectedSignatureSchemes.containsKey(sigSchemeCodePoint);
    }

    public static boolean isSigAlgorithmSupported(ASN1ObjectIdentifier oid) {
        return injectedOids.containsKey(oid.toString());
    }

    public static boolean isSigAndHashAlgorithmSupported(SignatureAndHashAlgorithm sigAndHashAlgorithm) {
        int codePoint = (sigAndHashAlgorithm.getHash() << 8) | sigAndHashAlgorithm.getSignature();
        return isSigSchemeSupported(codePoint);
    }

    /*
    public static int getCryptoHashAlgorithmIndex(int sigSchemeCodePoint) {
        return injectedSignatureSchemes.get(sigSchemeCodePoint).cryptoHashAlgorithmIndex;
    }*/

    public static boolean isParameterSupported(AsymmetricKeyParameter param) {
        for (SigAlgorithmInfo sig : injectedSignatureSchemes.values()) {
            if (sig.converter.isSupportedParameter(param))
                return true;
        }
        return false;
    }

    public static AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo keyInfo) throws IOException {
        AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();
        String algKey = algOID.toString();
        return injectedOids.get(algKey).converter.createPrivateKeyParameter(keyInfo);
    }

    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter param, ASN1Set attributes) throws IOException {
        for (SigAlgorithmInfo sig : injectedSignatureSchemes.values()) {
            if (sig.converter.isSupportedParameter(param))
                return sig.converter.createPrivateKeyInfo(param, attributes);
        }
        throw new RuntimeException("Unsupported private key params were given");
    }

    public static AsymmetricKeyParameter createPublicKeyParameter(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
        // ASN.1 => Lightweight BC public key params
        AlgorithmIdentifier algId = keyInfo.getAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();
        String algKey = algOID.toString();
        return injectedOids.get(algKey).converter.createPublicKeyParameter(keyInfo, defaultParams);
    }
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) throws IOException {
        // Lightweight BC public key params => ASN.1
        for (SigAlgorithmInfo sig : injectedSignatureSchemes.values()) {
            if (sig.converter.isSupportedParameter(publicKey))
                return sig.converter.createSubjectPublicKeyInfo(publicKey);
        }
        throw new RuntimeException("Unsupported public key params were given");
    }

    public static void configure(ConfigurableProvider provider) {

        for (SigAlgorithmInfo info : injected) {
            new Registrar(info).configure(provider);
        }
    }

    private static class Registrar extends AsymmetricAlgorithmProvider {
        SigAlgorithmInfo info;
        public Registrar(SigAlgorithmInfo info) {
            super();
            this.info = info;
        }

        @Override
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("Alg.Alias.Signature."+info.oid, info.name);
            provider.addAlgorithm("Alg.Alias.Signature.OID."+info.oid, info.name);

            // remove previous values in order to avoid the duplicate key exception
            if (provider instanceof java.security.Provider) {
                java.security.Provider p = (java.security.Provider)provider;
                p.remove("Signature."+info.name);
                p.remove("Alg.Alias.Signature." + info.oid);
                p.remove("Alg.Alias.Signature.OID." + info.oid);
            }
            // = provider.addSignatureAlgorithm(provider, "SPHINCSPLUS", PREFIX + "SignatureSpi$Direct", BCObjectIdentifiers.sphincsPlus);
            provider.addAlgorithm("Signature."+info.name, "org.bouncycastle.tls.injection.signaturespi.DirectSignatureSpi");
            provider.addAlgorithm("Alg.Alias.Signature." + info.oid, info.name);
            provider.addAlgorithm("Alg.Alias.Signature.OID." + info.oid, info.name);

            registerOid(provider, info.oid, info.name, info.infoToKeyConverter);;
            registerOidAlgorithmParameters(provider, info.oid, info.name);
            provider.addKeyInfoConverter(info.oid, info.infoToKeyConverter);
        }
    }

}
