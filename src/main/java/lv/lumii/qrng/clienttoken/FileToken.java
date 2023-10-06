package lv.lumii.qrng.clienttoken;

import org.cactoos.scalar.Sticky;
import org.cactoos.scalar.Unchecked;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;

public class FileToken implements Token {

    private final char[] password;
    private final String alias;
    private final Unchecked<KeyStore> keyStore;

    public FileToken(String fileName, String password, String alias) {
        this.password = password.toCharArray();
        this.alias = alias;
        this.keyStore = new Unchecked<>(new Sticky<>(() -> loadKeyStore(fileName)));
    }

    private KeyStore loadKeyStore(String fileName) throws Exception {
        KeyStore clientKeyStore = KeyStore.getInstance("PKCS12");
        // ^^^ If "Algorithm HmacPBESHA256 not available" error => need jdk16+ (new pkx format hash)

        File f = new File(fileName);
        FileInputStream instream = new FileInputStream(f);
        try {
            clientKeyStore.load(instream, password);
        } finally {
            instream.close();
        }
        return clientKeyStore;
    }

    @Override
    public Key key() {
        try {
            return this.keyStore.value().getKey(alias, password);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public char[] password() {
        return this.password;
    }

    @Override
    public byte[] signed(byte[] message) throws Exception {
        throw new UnsupportedOperationException("The private key (returned by the key() function) must be used to sign messages using this FileToken.");
    }

    @Override
    public Certificate[] certificateChain() {
        try {
            return this.keyStore.value().getCertificateChain(this.alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
}
