package org.bouncycastle.tls;

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

    private static class KEMInfo {
        private int codePoint;
        private final String jcaAlgorithm, standardName;

        KEMInfo(int codePoint, String jcaAlgorithm, String standardName) {
            this.codePoint = codePoint;
            this.jcaAlgorithm = jcaAlgorithm;
            this.standardName = standardName;
        }
    };
    private static final Map<Integer, KEMInfo> injectedKEMs = new HashMap<>();

    public static void injectKEM(int kemCodePoint, String jcaAlgorithmName, String standardName) {
        injectedKEMs.put(kemCodePoint, new KEMInfo(kemCodePoint, jcaAlgorithmName, standardName));
    }

    public static boolean isKEMSupported(int kemCodePoint) {
        return injectedKEMs.containsKey(kemCodePoint);
    }

    public static int[] getInjectedKEMsCodePoints() {
        // key set -> array of int
        return injectedKEMs.keySet().stream().mapToInt(i->i).toArray();
    }

    public static String getInjectedKEMStandardName(int kemCodePoint) {
        return injectedKEMs.get(kemCodePoint).standardName;
    }

}
