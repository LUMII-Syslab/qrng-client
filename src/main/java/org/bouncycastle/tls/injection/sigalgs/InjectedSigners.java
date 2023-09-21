package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * The class provides the ability inject signers (e.g., for PQC)
 * <p>
 * #pqc-tls #injection
 *
 * @author Sergejs Kozlovics
 */
public class InjectedSigners // TODO: => Factory
{


    public interface PrivateKeyToSignerFunction {
        TlsSigner invoke(JcaTlsCrypto crypto, PrivateKey sk);
    }


    private static Map<String, Object/*Function*/> injectedSigners = new HashMap<>();

    public static void injectSigner(String algorithmName, PrivateKeyToSignerFunction fn) {
        injectedSigners.put(algorithmName, fn);
    }

    public static void injectSigner(String algorithmName, SignerFunction fn) {
        injectedSigners.put(algorithmName, fn);
    }

    public static boolean isAlgorithmSupported(String name) {
        return injectedSigners.containsKey(name);
    }

    public static TlsSigner makeSigner(JcaTlsCrypto crypto, PrivateKey privateKey) {
        String algorithm = privateKey.getAlgorithm();

        Object fn = injectedSigners.get(algorithm);
        if (fn instanceof PrivateKeyToSignerFunction) {
            TlsSigner signer = ((PrivateKeyToSignerFunction) fn).invoke(crypto, privateKey);
            return signer;
        }
        if (fn instanceof SignerFunction) {
            byte[] sk = privateKey.getEncoded();
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(sk);

            byte[] sk2 = new byte[0];
            try {
                sk2 = info.getPrivateKey().getEncoded();


            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return new MyTlsSigner(crypto, sk2, (SignerFunction) fn);
        }
        throw new RuntimeException("Could not create a signer for algorithm "+algorithm);
    }

    public static Iterable<String> getInjectedSignerNames() {
        return injectedSigners.keySet();
    }
}
