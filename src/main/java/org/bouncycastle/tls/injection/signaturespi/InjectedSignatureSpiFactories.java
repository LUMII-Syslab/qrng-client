package org.bouncycastle.tls.injection.signaturespi;



import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PublicKey;
import java.security.SignatureSpi;
import java.util.Vector;

public class InjectedSignatureSpiFactories {

    private static Vector<SignatureSpiFromPublicOrPrivateKeyFactory> factories = new Vector<>();

    public static void registerFactory(SignatureSpiFromPublicOrPrivateKeyFactory factory) {
        factories.add(factory);
    }

    public static SignatureSpi createSignatureSpi(Key publicOrPrivateKey) throws InvalidKeyException {
        SignatureSpi result = null;
        for (SignatureSpiFromPublicOrPrivateKeyFactory f : factories) {
            try {
                result = f.newInstance(publicOrPrivateKey);
            }
            catch (Exception e) {
                //e.printStackTrace();
                // SignatureSpi could not been created with this factory, continue with the next one
            }
            if (result != null)
                break;
        }

        if (result == null) {
            throw new InvalidKeyException("No known SignatureSpi for the passed public key of type "+publicOrPrivateKey.getClass().getName());
        }

        return result;
    }

}