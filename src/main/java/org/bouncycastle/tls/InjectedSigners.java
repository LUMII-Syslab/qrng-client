package org.bouncycastle.tls;

import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.DefaultTlsCredentialedSigner;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.*;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * The class provides the ability inject signers (e.g., for PQC)
 *
 * #pqc-tls #injection
 * @author Sergejs Kozlovics
 */
public class InjectedSigners // TODO: => Factory
{
    public interface PrivateKeyToSignerFunction {
        TlsSigner invoke(JcaTlsCrypto crypto, PrivateKey sk);
    }
    private static Map<String, PrivateKeyToSignerFunction> injectedSigners = new HashMap<>();
    public static void injectSigner(String algorithmName, PrivateKeyToSignerFunction fn) {
        injectedSigners.put(algorithmName, fn);
    }

    public static boolean isAlgorithmSupported(String name) {
        return injectedSigners.containsKey(name);
    }
    public static TlsSigner makeSigner(JcaTlsCrypto crypto, PrivateKey privateKey)
    {
        String algorithm = privateKey.getAlgorithm();
        TlsSigner signer = injectedSigners.get(algorithm).invoke(crypto, privateKey);
        return signer;
    }

    public static Iterable<String> getInjectedSignerNames() {
        return injectedSigners.keySet();
    }
}
