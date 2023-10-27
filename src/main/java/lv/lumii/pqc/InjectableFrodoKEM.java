package lv.lumii.pqc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.frodo.*;
import org.bouncycastle.tls.injection.kems.KEM;
import org.openquantumsafe.Pair;

import java.security.SecureRandom;

public class InjectableFrodoKEM implements KEM {

    public static final int CODE_POINT = 0x0200; // oqs_frodo640aes_codepoint
    public static final String NAME = "FrodoKEM-640-AES";
    //private org.openquantumsafe.KeyEncapsulation kem;
    // ^^^ if via liboqs + JNI + DLL
    FrodoKeyPairGenerator kemGen; // - if via BC

    public InjectableFrodoKEM() {
        // String kemName = "FrodoKEM-640-AES";
        //this.kem = new org.openquantumsafe.KeyEncapsulation(kemName);
        // ^^^ if via liboqs + JNI + DLL

        this.kemGen = new FrodoKeyPairGenerator();
        this.kemGen.init(new FrodoKeyGenerationParameters(new SecureRandom(), FrodoParameters.frodokem640aes));
    }

    @Override
    public Pair<byte[], byte[]> keyGen() {
        // at the client side:

        // if via liboqs JNI + DLL:
        //byte[] myPublicKey = kem.generate_keypair().clone();
        //byte[] myPrivateKey = kem.export_secret_key().clone();


        // if pure Java (BouncyCastle):
        AsymmetricCipherKeyPair kp = kemGen.generateKeyPair();
        FrodoPublicKeyParameters pubParams = (FrodoPublicKeyParameters) (kp.getPublic());
        FrodoPrivateKeyParameters privParams = (FrodoPrivateKeyParameters) (kp.getPrivate());
        //variant: byte[] encoded = pubParams.getEncoded();
        //variant: byte[] encoded2 = pubParams.getPublicKey();
        byte[] myPublicKey = pubParams.getPublicKey().clone();//publicKey.clone();
        byte[] myPrivateKey = privParams.getPrivateKey().clone();

        return new Pair<>(myPublicKey, myPrivateKey);
    }

    @Override
    public Pair<byte[], byte[]> encapsulate(byte[] partnerPublicKey) {
        // at the server side:
        // if via liboqs JNI + DLL:
        //Pair<byte[], byte[]> pair = kem.encap_secret(partnerPublicKey);
        //byte[] ciphertext = pair.getLeft();
        //byte[] semiSecret = pair.getRight();
        //return new Pair<>(semiSecret, ciphertext);


        FrodoKEMGenerator gen = new FrodoKEMGenerator(new SecureRandom());
        FrodoPublicKeyParameters pub = new FrodoPublicKeyParameters(FrodoParameters.frodokem640aes, partnerPublicKey);

        SecretWithEncapsulation secretWithEncapsulation = gen.generateEncapsulated(pub);

        //this.mySecret = secretWithEncapsulation.getSecret(); -- will be assigned automatically

        return new Pair<>(secretWithEncapsulation.getSecret(), secretWithEncapsulation.getEncapsulation());

    }

    @Override
    public byte[] decapsulate(byte[] secretKey, byte[] ciphertext) {
        // at the client side

        byte[] sharedSecret;

        // assert: this.secretKey == secretKey
        // if via libqs JNI + DLL:
        //sharedSecret = kem.decap_secret(ciphertext);

        // if BC:
        FrodoPrivateKeyParameters priv = new FrodoPrivateKeyParameters(FrodoParameters.frodokem640aes, secretKey);
        FrodoKEMExtractor ext = new FrodoKEMExtractor(priv);
        sharedSecret = ext.extractSecret(ciphertext);

        // if via liboqs JNI + DLL:
        // this.kem.dispose_KEM();

        return sharedSecret;
    }
}
