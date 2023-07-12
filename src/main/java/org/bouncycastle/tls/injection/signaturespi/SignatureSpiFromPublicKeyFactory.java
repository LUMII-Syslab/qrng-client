package org.bouncycastle.tls.injection.signaturespi;

import java.security.PublicKey;
import java.security.SignatureSpi;

/**
 * A factory that is able to create SignatureSpi-s from PublicKey-s.
 * Factories are used to create SignatureSpi-s from DirectSignatureSpi.
 * Factories have to be registered within InjectedSignatureSpiFactories.
 *
 * #pqc-tls #injection
 *
 * @author Sergejs Kozlovics
 */
public interface SignatureSpiFromPublicKeyFactory {
    SignatureSpi newInstance(PublicKey publicKey);
}
