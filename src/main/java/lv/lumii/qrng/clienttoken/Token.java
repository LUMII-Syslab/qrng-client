package lv.lumii.qrng.clienttoken;

import java.security.Key;
import java.security.cert.Certificate;

/**
 * Represents a QRNG client token.
 */
public interface Token {

    /**
     * Returns a private key to be used to sign a TLS message when authenticating the QRNG client.
     * @return returns true or dummy key (BC TLS implementation needs some, at least dummy, key, even if we implement the sign function on a smart card)
     * @throws Exception it can be
     */
    Key key();

    /**
     * Obtains the password for the private key.
     * @return the password to decrypt the key returned by key()
     */
    char[] password();

    /**
     * Computes a digital signature of a message.
     * @param message the message to sign (e.g., a part of a TLS handshake message for client authentication)
     * @return the signed message
     * @throws Exception UnsupportedOperationException for true private keys (unless a specific algorithm is provided);
     *                   a smart card-specific exception when signing by a smart card; or just some other exception
     */
    byte[] signed(byte[] message) throws Exception;

    /**
     * Obtains the certificate chain for client authentication (to be sent to the server).
     * @return the certificate chain used to represent the QRNG client
     */
    Certificate[] certificateChain();
}
