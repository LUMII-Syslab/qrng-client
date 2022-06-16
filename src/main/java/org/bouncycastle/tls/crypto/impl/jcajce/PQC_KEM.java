package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.frodo.*;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

import java.io.IOException;
import java.security.SecureRandom;

public class PQC_KEM implements TlsAgreement // all by SK
{
    // from the client point of view
    private JcaTlsCrypto crypto;
    // private org.openquantumsafe.KeyEncapsulation kem; - if via liboqs + JNI + DLL

    FrodoKeyPairGenerator kemGen;
    private byte[] clientPublicKey = null;
    private byte[] clientPrivateKey = null;
    private byte[] serverEnsapsulated = null;

    public PQC_KEM(JcaTlsCrypto crypto, String kemName)
    {
        this.crypto = crypto;
        // this.kem = new KeyEncapsulation(kemName); - if via liboqs + JNI + DLL
        this.kemGen = new FrodoKeyPairGenerator();
        this.kemGen.init(new FrodoKeyGenerationParameters(new SecureRandom(), FrodoParameters.frodokem19888r3));
    }

    public byte[] generateEphemeral() throws IOException
    {
        // if via liboqs JNI + DLL:
        //this.clientPublicKey = kem.generate_keypair();
        //this.clientPrivateKey = kem.export_secret_key().clone();

        // if pure Java (BouncyCastle):
        AsymmetricCipherKeyPair kp = kemGen.generateKeyPair();
        FrodoPublicKeyParameters pubParams = (FrodoPublicKeyParameters)(kp.getPublic());
        FrodoPrivateKeyParameters privParams = (FrodoPrivateKeyParameters)(kp.getPrivate());
        this.clientPublicKey = pubParams.publicKey.clone();
        this.clientPrivateKey = privParams.getPrivateKey().clone();

        return this.clientPublicKey;

    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.serverEnsapsulated = peerValue;
    }

    public TlsSecret calculateSecret() throws IOException
    {
        // if via liboqs JNI + DLL:
        //byte[] shared_secret_client = kem.decap_secret(this.serverEnsapsulated);
        //this.kem.dispose_KEM();
        //return new JceTlsSecret(this.crypto, shared_secret_client);


        // if pure Java (BouncyCastle):
        FrodoPrivateKeyParameters priv = new FrodoPrivateKeyParameters(FrodoParameters.frodokem19888r3, this.clientPrivateKey);
        FrodoKEMExtractor ext = new FrodoKEMExtractor(priv);

        byte[] shared_secret_client2 = ext.extractSecret(this.serverEnsapsulated);

        return new JceTlsSecret(this.crypto, shared_secret_client2);

    }
}
