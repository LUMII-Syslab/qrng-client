package org.bouncycastle.tls;

import org.bouncycastle.asn1.*;

import java.util.*;

/**
 * A class representing injected signature algorithms. #pqc-tls #injection
 *
 * @author Sergejs Kozlovics
 */
public class InjectedSigAlgorithms
{
    static class OidWithSigAndHash {
        public final ASN1ObjectIdentifier oid;
        public final SignatureAndHashAlgorithm sigAndHash;

        public final int signatureSchemeCodePoint;
        public final short cryptoHashAlgorithmIndex;
            // ^^^ corresponding to org.bouncycastle.tls.crypto.impl.CryptoHashAlgorithm
            //     (e.g., CryptoHashAlgorithm.sha256 for rainbowIclassic);
            //     use -1 or 8 (HashAlgorithm.Intrinsic), if the hash algorithm is built-in into the signature scheme
            //     (e.g., for sphincsshake256128frobust)
        public OidWithSigAndHash(ASN1ObjectIdentifier oid, SignatureAndHashAlgorithm sigAndHash,
                                 int signatureSchemeCodePoint,
                                 short cryptoHashAlgorithmIndex) {
            this.oid = oid;
            this.sigAndHash = sigAndHash;
            this.signatureSchemeCodePoint = signatureSchemeCodePoint;
            this.cryptoHashAlgorithmIndex = cryptoHashAlgorithmIndex;
        }
    }
    private static final Vector<OidWithSigAndHash> injected = new Vector<>();
    private static final Map<Integer, OidWithSigAndHash> injectedSignatureSchemes = new HashMap<>();

    public static void injectSigAndHashAlgorithm(ASN1ObjectIdentifier oid, SignatureAndHashAlgorithm sigAndHash,
                                                 int signatureSchemeCodePoint, // e.g., oqs_sphincsshake256128frobust
                                                 short cryptoHashAlgorithmIndex) {
        OidWithSigAndHash newItem = new OidWithSigAndHash(oid, sigAndHash, signatureSchemeCodePoint, cryptoHashAlgorithmIndex);
        injected.add(newItem);
        injectedSignatureSchemes.put(signatureSchemeCodePoint, newItem);
    }

    public static Iterable<OidWithSigAndHash> getInjectedSigAndHashAlgorithms() {
        return injected;
    }

    public static boolean isSigSchemeSupported(int sigSchemeCodePoint) {
        return injectedSignatureSchemes.containsKey(sigSchemeCodePoint);
    }

    public static boolean isSigAndHashAlgorithmSupported(SignatureAndHashAlgorithm sigAndHashAlgorithm) {
        return injected.contains(sigAndHashAlgorithm);
    }

    public static short getCryptoHashAlgorithmIndex(int sigSchemeCodePoint) {
        return injectedSignatureSchemes.get(sigSchemeCodePoint).cryptoHashAlgorithmIndex;
    }
}
