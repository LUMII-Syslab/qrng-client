package org.bouncycastle.tls;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

import java.io.IOException;
import java.security.PrivateKey;
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

    public interface TlsAgreementFunction {
        TlsAgreement invoke(JcaTlsCrypto crypto, int kemCodePoint);
    }

    private record KEMInfo(/*ASN1ObjectIdentifier oid,*/ int codePoint, /*String jcaAlgorithm,*/ String standardName,
                                                         TlsAgreementFunction tlsAgreementFunction) {
    }

    ;
    private static final Vector<Integer> injectedCodePoints = new Vector<>();
    private static final Map<Integer, KEMInfo> injectedKEMs = new HashMap<>();

    public static void injectKEM(int kemCodePoint, //String jcaAlgorithmName,
                                 String standardName, TlsAgreementFunction tlsAgreementFunction) {
        KEMInfo info = new KEMInfo(kemCodePoint, /*jcaAlgorithmName,*/ standardName, tlsAgreementFunction);
        injectedCodePoints.add(kemCodePoint);
        injectedKEMs.put(kemCodePoint, info);
    }

    public static boolean isKEMSupported(int kemCodePoint) {
        return injectedKEMs.containsKey(kemCodePoint);
    }


    public static int[] getInjectedKEMsCodePoints() {
        // key set -> array of int
        return injectedCodePoints.stream().mapToInt(i->i).toArray();
    }

    public static String getInjectedKEMStandardName(int kemCodePoint) {
        return injectedKEMs.get(kemCodePoint).standardName;
    }

    public static TlsAgreement getTlsAgreement(JcaTlsCrypto crypto, int kemCodePoint) {
        return injectedKEMs.get(kemCodePoint).tlsAgreementFunction.invoke(crypto, kemCodePoint);
    }

/*    public static boolean isParameterSupported(AsymmetricKeyParameter param) {
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
    }*/
}
