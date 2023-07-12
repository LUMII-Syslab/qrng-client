package org.bouncycastle.tls.injection.signaturespi;



import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureSpi;
import java.util.Vector;

public class InjectedSignatureSpiFactories {

    private static Vector<SignatureSpiFromPublicKeyFactory> factories = new Vector<>();

    public static void registerFactory(SignatureSpiFromPublicKeyFactory factory) {
        factories.add(factory);
    }

    public static SignatureSpi createSignatureSpi(PublicKey publicKey) throws InvalidKeyException {
        SignatureSpi result = null;
        for (SignatureSpiFromPublicKeyFactory f : factories) {
            try {
                result = f.newInstance(publicKey);
            }
            catch (Exception e) {
                e.printStackTrace();
                // SignatureSpi could not been created with this factory, continue with the next one
            }
            if (result != null)
                break;
        }

        if (result == null) {
            throw new InvalidKeyException("No known SignatureSpi for the passed public key of type "+publicKey.getClass().getName());
        }

        return result;
    }

}