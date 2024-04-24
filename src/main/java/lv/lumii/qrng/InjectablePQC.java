package lv.lumii.qrng;

import lv.lumii.pqc.InjectableFrodoKEM;
import lv.lumii.smartcard.InjectableSmartCardRSA;
import lv.lumii.pqc.InjectableSphincsPlus;
import lv.lumii.smartcard.SmartCardSignFunction;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.sphincsplus.*;
import org.bouncycastle.tls.injection.InjectableAlgorithms;
import org.bouncycastle.tls.injection.InjectableKEMs;
import org.bouncycastle.tls.injection.InjectionPoint;
import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * The class for injecting PQC algorithms used for our experiments (~post-quantum agility)
 * <p>
 *
 * @author Sergejs Kozlovics
 */
public class InjectablePQC {





    public static void inject(boolean insteadDefaultKems, SmartCardSignFunction smartCardSignFunction) {
        // PQC signatures are huge; increasing the max handshake size:
        System.setProperty("jdk.tls.maxHandshakeMessageSize", String.valueOf(32768 * 32));

        InjectableSphincsPlus mySphincs = new InjectableSphincsPlus();
        InjectableSmartCardRSA myRSA = new InjectableSmartCardRSA(smartCardSignFunction);

        InjectableAlgorithms algs = new InjectableAlgorithms()
                .withSigAlg(mySphincs.name(), mySphincs.aliases(), mySphincs.oid(), mySphincs.codePoint(), mySphincs)
                .withSigAlg("SHA256WITHRSA", List.of(new String[]{}), myRSA.oid(), myRSA.codePoint(), myRSA)
                .withSigAlg("RSA", List.of(new String[]{}), myRSA.oid(), myRSA.codePoint(), myRSA)
                //.withSigAlg("SHA256WITHRSA", myRSA.oid(), myRSA.codePoint(), myRSA)
                //.withSigAlg("RSA", myRSA.oid(), myRSA.codePoint(), myRSA)
                // RSA must be _after_ SHA256WITHRSA, since they share the same code point, and BC TLS uses "RSA" as a name for finding client RSA certs (however, SHA256WITHRSA is also needed for checking client cert signatures)
                .withKEM(InjectableFrodoKEM.NAME, InjectableFrodoKEM.CODE_POINT,
                        InjectableFrodoKEM::new, InjectableKEMs.Ordering.BEFORE);
        if (insteadDefaultKems)
            algs = algs.withoutDefaultKEMs();


        InjectionPoint.theInstance().push(algs);
    }




    ///// TESTS /////

    public static String byteArrayToString(byte[] a) {
        return byteArrayToString(a, "");
    }

    public static String byteArrayToString(byte[] a, String delim) {
        String s = "";
        for (byte b : a) {
            if (s.length() > 0)
                s += delim;
            s += String.format("%02x", b);
        }
        return s;
    }

    public static byte[] hexStringToByteArray(String s) {
        s = s.replaceAll(" ", ""); // remove all spaces
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static void main(String args[]) {

        /* if pure-Java BC:

        InjectableFrodoKEMAgreement f1 = new InjectableFrodoKEMAgreement(null, "FrodoKEM-640-AES", false);
        InjectableFrodoKEMAgreement f2 = new InjectableFrodoKEMAgreement(null, "FrodoKEM-640-AES", true);
        Pair<byte[],byte[]> p = f1.keyGen();

        Pair<byte[], byte[]> secEnc = f2.encapsulate(p.getLeft()); // p.getLeft === public key;

        System.out.println("SERVER SECRET="+byteArrayToString(secEnc.getLeft()));
        System.out.println("SERVER ENC="+byteArrayToString(Arrays.copyOfRange(secEnc.getRight(), 0, 20))+"...");

        byte[] clientSecret = f1.decapsulate(p.getRight(), secEnc.getRight());
        System.out.println("CLIENT SECRET="+byteArrayToString(clientSecret));
        */

        // if via liboqs JNI + DLL:

        KeyEncapsulation kem1 = new org.openquantumsafe.KeyEncapsulation("FrodoKEM-640-SHAKE");
        KeyEncapsulation kem2 = new org.openquantumsafe.KeyEncapsulation("FrodoKEM-640-SHAKE");

        byte[] pk1 = kem1.generate_keypair();
        byte[] sk1 = kem1.export_secret_key();

        byte[] pk2 = kem2.generate_keypair();
        byte[] sk2 = kem2.export_secret_key();

        // pk1 =>
        // <= pk2

        Pair<byte[], byte[]> pair1 = kem1.encap_secret(pk2);
        byte[] my1 = pair1.getRight();
        byte[] enc1 = pair1.getLeft();

        Pair<byte[], byte[]> pair2 = kem2.encap_secret(pk1);
        byte[] my2 = pair2.getRight();
        byte[] enc2 = pair2.getLeft();

        byte[] d1 = kem1.decap_secret(enc2);
        byte[] d2 = kem2.decap_secret(enc1);

        System.out.println(byteArrayToString(d1));
        System.out.println(byteArrayToString(my1));
        System.out.println(byteArrayToString(d2));
        System.out.println(byteArrayToString(my2));


        for (String s : org.openquantumsafe.Sigs.get_enabled_sigs()) {
            System.out.println("SIG " + s);
        }
        String pkStr = "8776619e7fc2ca19b0be40157190208680007c01b855256123e2866ae71ad34616af34d2a08542a6fcd8b9ceab9ea4fa4bf640a5cd866f87aad16a971603e173";
        byte[] sk = hexStringToByteArray(pkStr);
        byte[] pk = Arrays.copyOfRange(sk, sk.length - 32, sk.length);

        final String OQS_SIG_NAME = "SPHINCS+-SHA2-128f-simple";

        org.openquantumsafe.Signature oqsSigner = new org.openquantumsafe.Signature(
                OQS_SIG_NAME);
        oqsSigner.generate_keypair();
        pk = oqsSigner.export_public_key();
        sk = oqsSigner.export_secret_key();
        System.out.println("OQS KEYPAIR: " + sk.length + " " + pk.length);
        System.out.println("OQS PK " + byteArrayToString(pk));
        System.out.println("OQS SK " + byteArrayToString(sk));


        final SPHINCSPlusParameters sphincsPlusParameters = SPHINCSPlusParameters.sha2_128f;//.sha2_128f_simple;

        SPHINCSPlusKeyPairGenerator generator = new SPHINCSPlusKeyPairGenerator();
        SPHINCSPlusKeyGenerationParameters params = new SPHINCSPlusKeyGenerationParameters(new SecureRandom(), sphincsPlusParameters);
        generator.init(params);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        SPHINCSPlusPublicKeyParameters _pk = (SPHINCSPlusPublicKeyParameters) keyPair.getPublic();
        SPHINCSPlusPrivateKeyParameters _sk = (SPHINCSPlusPrivateKeyParameters) keyPair.getPrivate();

        //// comment to use LibOQS-generated keys =>
        pk = _pk.getEncoded();
        pk = Arrays.copyOfRange(pk, 4, pk.length);
        sk = _sk.getEncoded();
        sk = Arrays.copyOfRange(sk, 4, sk.length);
        System.out.println("BC5 KEYPAIR: " + sk.length + " " + pk.length);
        System.out.println("BC PK " + byteArrayToString(pk));
        System.out.println("BC SK " + byteArrayToString(sk));
        //// <= comment to use LibOQS-generated keys

        // TODO: compile and test with latest liboqs 0.8.1-dev
        // https://github.com/open-quantum-safe/liboqs/blob/main/RELEASE.md


    }

}
