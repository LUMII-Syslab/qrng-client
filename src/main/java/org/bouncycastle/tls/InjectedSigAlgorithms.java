package org.bouncycastle.tls;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.util.*;

/**
 * A class representing injected signature algorithms. #pqc-tls #injection
 *
 * @author Sergejs Kozlovics
 */
public class InjectedSigAlgorithms
{
    /**
     * @param cryptoHashAlgorithmIndex corresponds to org.bouncycastle.tls.crypto.impl.CryptoHashAlgorithm
     *                                 (e.g., CryptoHashAlgorithm.sha256 for rainbowIclassic);
     *                                 use -1 or 8 (HashAlgorithm.Intrinsic), if the hash algorithm is
     *                                 built-in into the signature scheme (e.g., for sphincsshake256128frobust)
     */
    record SigAlgorithmInfo(ASN1ObjectIdentifier oid, SignatureAndHashAlgorithm sigAndHash,
                            int signatureSchemeCodePoint, short cryptoHashAlgorithmIndex,
                            InjectedConverter converter) {

        public ASN1ObjectIdentifier oid() {
            return this.oid;
        }

        public SignatureAndHashAlgorithm signatureAndHashAlgorithm() {
            return this.sigAndHash;
        }
    }
    private static final Vector<SigAlgorithmInfo> injected = new Vector<>();
    private static final Map<Integer, SigAlgorithmInfo> injectedSignatureSchemes = new HashMap<>();
    private static final Map<String, SigAlgorithmInfo> injectedOids = new HashMap<>();

    public static void injectSigAndHashAlgorithm(ASN1ObjectIdentifier oid, SignatureAndHashAlgorithm sigAndHash,
                                                 int signatureSchemeCodePoint, // e.g., oqs_sphincsshake256128frobust
                                                 short cryptoHashAlgorithmIndex,
                                                 InjectedConverter converter) {
        SigAlgorithmInfo newItem = new SigAlgorithmInfo(oid, sigAndHash, signatureSchemeCodePoint,
                cryptoHashAlgorithmIndex, converter);
        injected.add(newItem);
        injectedSignatureSchemes.put(signatureSchemeCodePoint, newItem);
        injectedOids.put(oid.toString(), newItem);
    }

    public static Iterable<SigAlgorithmInfo> getInjectedSigAndHashAlgorithms() {
        return injected;
    }

    public static boolean isSigSchemeSupported(int sigSchemeCodePoint) {
        return injectedSignatureSchemes.containsKey(sigSchemeCodePoint);
    }

    public static boolean isSigAlgorithmSupported(ASN1ObjectIdentifier oid) {
        return injectedOids.containsKey(oid.toString());
    }

    public static boolean isSigAndHashAlgorithmSupported(SignatureAndHashAlgorithm sigAndHashAlgorithm) {
        return injected.contains(sigAndHashAlgorithm);
    }

    public static short getCryptoHashAlgorithmIndex(int sigSchemeCodePoint) {
        return injectedSignatureSchemes.get(sigSchemeCodePoint).cryptoHashAlgorithmIndex;
    }

    public static boolean isParameterSupported(AsymmetricKeyParameter param) {
        for (SigAlgorithmInfo sig : injectedSignatureSchemes.values()) {
            if (sig.converter.isSupportedParameter(param))
                return true;
        }
        return false;
    }

    public static AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo keyInfo) {
        AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();
        return injectedOids.get(algOID).converter.createPrivateKeyParameter(keyInfo);
    }

    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter param) {
        for (SigAlgorithmInfo sig : injectedSignatureSchemes.values()) {
            if (sig.converter.isSupportedParameter(param))
                return sig.converter.createPrivateKeyInfo(param);
        }
        throw new RuntimeException("Unsupported private key params were given");
    }

    public static AsymmetricKeyParameter createPublicKeyParameter(SubjectPublicKeyInfo keyInfo, Object defaultParams) {
        // ASN.1 => Lightweight BC public key params
        AlgorithmIdentifier algId = keyInfo.getAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();
        return injectedOids.get(algOID).converter.createPublicKeyParameter(keyInfo, defaultParams);
    }
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) {
        // Lightweight BC public key params => ASN.1
        for (SigAlgorithmInfo sig : injectedSignatureSchemes.values()) {
            if (sig.converter.isSupportedParameter(publicKey))
                return sig.converter.createSubjectPublicKeyInfo(publicKey);
        }
        throw new RuntimeException("Unsupported public key params were given");
    }

}
