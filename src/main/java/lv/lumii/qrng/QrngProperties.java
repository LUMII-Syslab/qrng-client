package lv.lumii.qrng;

import org.cactoos.scalar.Sticky;
import org.cactoos.scalar.Unchecked;

import java.io.*;
import java.security.KeyStore;
import java.util.Properties;

public class QrngProperties {
    private String mainDirectory;
    private Unchecked<Properties> properties;

    public QrngProperties(String mainDirectory) {
        System.out.println("MAIN "+mainDirectory);
        this.mainDirectory = mainDirectory;
        this.properties = new Unchecked<>(new Sticky<>(
                () -> loadPropertiesFile(mainDirectory + File.separator + "qrng.properties")));
    }

    private Properties loadPropertiesFile(String fileName) {
        Properties p = new Properties();

        try {
            p.load(new BufferedReader(new FileReader(fileName)));
        } catch (IOException e) {
            QrngClient.logger.error("Could not load QRNG properties from "+fileName, e);
        }

        return p;
    }

    private String fileNameProperty(String key, String defaultValue) {
        String fileName = this.properties.value().getProperty(key, defaultValue);
        File f = new File(fileName);
        if (!f.isFile())
            f = new File(mainDirectory+File.separator+fileName);
        return f.getAbsolutePath();
    }


    public String host() throws Exception {
        String url = properties.value().getProperty("host");
        if (url == null)
            throw new Exception("The QRNG 'host' is not specified in qrng.properties");
        return url;
    }

    public int port() throws Exception {
        int defaultPort = 443;
        String s = properties.value().getProperty("port", defaultPort+"");
        try {
            int result = Integer.parseInt(s);
            if (result<=0)
                return defaultPort;
            return result;
        }
        catch (Exception e) {
            return defaultPort;
        }
    }

    public int clientBufferSize() {
        int defaultSize = 10*2048;
        String s = properties.value().getProperty("clientBufferSize", defaultSize+"");
        try {
            int result = Integer.parseInt(s);
            if (result<=0)
                return defaultSize;
            return result;
        }
        catch (Exception e) {
            return defaultSize;
        }
    }

    public QrngClientToken clientToken() {
        return new QrngClientToken(
                fileNameProperty("token", "token.keystore"),
                this.properties.value().getProperty("tokenPassword", "token-pass"), // token-pass
                this.properties.value().getProperty("tokenAlias", "qrng_user") // qrng_user
        );
    }

    public KeyStore trustStore() throws Exception {

        String fileName = fileNameProperty("ca", "ca.truststore");
        File f = new File(fileName);

        String password = properties.value().getProperty("caPassword", "ca-truststore-pass"); // ca-truststore-pass

        KeyStore trustStore = KeyStore.getInstance(f, password.toCharArray());
        return trustStore;
    }


}
