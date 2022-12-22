package org.bouncycastle.tls;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.io.IOException;
import java.util.*;
import java.util.logging.Logger;

/**
 * The class for storing information of injected key encapsulation mechanisms (KEMs) ~ named groups ~ curves.
 * (For the needs of Post-Quantum Cryptography, DH/ECC groups/curves have been replaced by KEMs.)
 *
 * KEMI is used by NamedGroupInfo (as an extension) and JcaTLsCrypto (which relies
 * on KEM.isInjectedKEMCodePoint).
 *
 * #pqc-tls #injection
 * @author Sergejs Kozlovics
 */
public class InjectedKEMs
{
    private static final Logger LOG = Logger.getLogger(InjectedKEMs.class.getName());

    private record KEMInfo(ASN1ObjectIdentifier oid, int codePoint, String jcaAlgorithm, String standardName,
                           InjectedConverter converter) {
    }

    ;
    private static final Map<Integer, KEMInfo> injectedKEMs = new HashMap<>();
    private static final Map<String, KEMInfo> injectedOids = new HashMap<>();

    public static void injectKEM(ASN1ObjectIdentifier oid, int kemCodePoint, String jcaAlgorithmName,
                                 String standardName, InjectedConverter privateKeyParamsFn) {
        KEMInfo info = new KEMInfo(oid, kemCodePoint, jcaAlgorithmName, standardName, privateKeyParamsFn);
        injectedKEMs.put(kemCodePoint, info);
        injectedOids.put(oid.toString(), info);
    }

    public static boolean isKEMSupported(int kemCodePoint) {
        return injectedKEMs.containsKey(kemCodePoint);
    }

    public static boolean isKEMSupported(ASN1ObjectIdentifier oid) {
        return injectedKEMs.containsKey(oid.toString());
    }

    public static int[] getInjectedKEMsCodePoints() {
        // key set -> array of int
        return injectedKEMs.keySet().stream().mapToInt(i->i).toArray();
    }

    public static String getInjectedKEMStandardName(int kemCodePoint) {
        return injectedKEMs.get(kemCodePoint).standardName;
    }

    public static boolean isParameterSupported(AsymmetricKeyParameter param) {
        for (KEMInfo kem : injectedKEMs.values()) {
            if (kem.converter().isSupportedParameter(param))
                return true;
        }
        return false;
    }

    public static AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo keyInfo) throws IOException {
        AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();
        return injectedOids.get(algOID).converter.createPrivateKeyParameter(keyInfo);
    }

    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter param, ASN1Set attributes) throws IOException {
        for (KEMInfo kem : injectedKEMs.values()) {
            if (kem.converter.isSupportedParameter(param))
                return kem.converter.createPrivateKeyInfo(param, attributes);
        }
        throw new RuntimeException("Unsupported private key params were given");
    }

    public static AsymmetricKeyParameter createPublicKeyParameter(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
        // ASN.1 => Lightweight BC public key params
        AlgorithmIdentifier algId = keyInfo.getAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();
        return injectedOids.get(algOID).converter.createPublicKeyParameter(keyInfo, defaultParams);
    }
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) throws IOException {
        // Lightweight BC public key params => ASN.1
        for (KEMInfo kem : injectedKEMs.values()) {
            if (kem.converter.isSupportedParameter(publicKey))
                return kem.converter.createSubjectPublicKeyInfo(publicKey);
        }
        throw new RuntimeException("Unsupported public key params were given");
    }
}
