package lv.lumii.qrng;

import java.security.cert.Certificate;
import org.cactoos.scalar.Sticky;
import org.cactoos.scalar.Unchecked;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;

public class QrngClientToken {

    private char[] password;
    private String alias;
    private Unchecked<KeyStore> keyStore;

    public QrngClientToken(String fileName, String password, String alias) {
        this.password = password.toCharArray();
        this.alias = alias;
        this.keyStore = new Unchecked<>(new Sticky<>(()->loadKeyStore(fileName)));
    }

    private KeyStore loadKeyStore(String fileName) throws Exception {
        KeyStore clientKeyStore  = KeyStore.getInstance("PKCS12");
        // ^^^ If "Algorithm HmacPBESHA256 not available" error => need jdk16+ (new pkx format hash)

        File f = new File(fileName);
        FileInputStream instream = new FileInputStream(f);
        try {
            clientKeyStore.load(instream, password);
        }
        finally {
            instream.close();
        }
        return clientKeyStore;
    }

    public Key key() throws Exception {
        return this.keyStore.value().getKey(alias, password);
    }

    public char[] password() {
        return this.password;
    }

    public Certificate[] certificateChain() throws Exception {
        Certificate[] arr = this.keyStore.value().getCertificateChain(this.alias);
        return arr;
    }
}
