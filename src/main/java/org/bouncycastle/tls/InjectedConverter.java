package org.bouncycastle.tls;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.io.IOException;

/**
 * The interface used by BC to convert lightweight BC (public and private) key params
 * to the ASN.1 notation ("info") and vice versa.
 *
 * #pqc-tls #injection
 * @author Sergejs Kozlovics
 */
public interface InjectedConverter {
    /**
     * Checks whether the given lightweight BC key param (public or private) can be converted to ASN.1 ("info").
     * @param privateKey key parameter that has to be converted to ASN.1
     * @return returns true, iff param is of known type and can be converted to PrivateKeyInfo
     */
    boolean isSupportedParameter(AsymmetricKeyParameter privateKey);
    AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo keyInfo) throws IOException; // ASN.1 => Lightweight BC private key params
    PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes) throws IOException; // Lightweight BC private key params => ASN.1

    AsymmetricKeyParameter createPublicKeyParameter(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException; // ASN.1 => Lightweight BC public key params
    SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) throws IOException; // Lightweight BC public key params => ASN.1
}
