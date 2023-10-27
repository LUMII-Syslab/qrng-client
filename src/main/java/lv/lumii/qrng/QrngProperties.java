package lv.lumii.qrng;

import lv.lumii.qrng.clienttoken.FileToken;
import lv.lumii.qrng.clienttoken.Token;
import org.cactoos.scalar.Sticky;
import org.cactoos.scalar.Unchecked;
import org.slf4j.Logger;

import java.io.*;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class QrngProperties {

    public static Logger logger = QrngClient.logger; // one common logger
    private final String mainDirectory;
    private final Map<String, ClientTokenFactory> clientTokenFactories;
    private final Unchecked<Properties> properties;
    private final Unchecked<Token> clientToken;

    public QrngProperties(String mainDirectory) {
        this(mainDirectory, new HashMap<>());
    }

    public QrngProperties(String mainDirectory, Map<String, ClientTokenFactory> clientTokenFactories) {
        this.mainDirectory = mainDirectory;
        this.clientTokenFactories = clientTokenFactories;
        this.properties = new Unchecked<>(new Sticky<>(
                () -> loadPropertiesFile(mainDirectory + File.separator + "qrng.properties")));
        this.clientToken = new Unchecked<>(new Sticky<>(
                () -> loadClientToken()));
    }

    private Properties loadPropertiesFile(String fileName) {
        Properties p = new Properties();

        try {
            p.load(new BufferedReader(new FileReader(fileName)));
        } catch (IOException e) {
            logger.error("Could not load QRNG properties from "+fileName, e);
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

    public boolean pqcKemRequired() {
        boolean defaultValue = true;
        String s = properties.value().getProperty("pqcKemRequired", defaultValue+"");
        try {
            boolean result = Boolean.parseBoolean(s);
            return result;
        }
        catch (Exception e) {
            return defaultValue;
        }
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

    public Token clientToken() {
        return this.clientToken.value();
    }

    private Token loadClientToken() {
        String token = properties.value().getProperty("token", "");

        int i = token.indexOf(':');
        if (i>=0) {
            String factoryName = token.substring(0, i);
            if (clientTokenFactories.containsKey(factoryName)) {
                // e.g., "smartcard:*"
                String tokenLocation = token.substring(i+1);
                logger.info("Loading the client token using the '"+factoryName+"' factory from '"+tokenLocation+"'.");
                // e.g., loading the token from the smartcard reader with the name/mask "*"
                return clientTokenFactories.get(factoryName).clientToken(tokenLocation);
            }
        }

        logger.info("Loading client token from file.");
        // if factory was not used, assume this is a file token...
        return new FileToken(
                fileNameProperty("token", "token.keystore"),
                this.properties.value().getProperty("tokenPassword", "client-keystore-pass"),
                this.properties.value().getProperty("tokenAlias", "client")
        );
    }

    public KeyStore trustStore() throws Exception {

        String fileName = fileNameProperty("ca", "ca.truststore");
        File f = new File(fileName);

        String password = properties.value().getProperty("caPassword", "ca-truststore-pass"); // ca-truststore-pass

        KeyStore trustStore = KeyStore.getInstance(f, password.toCharArray());
        return trustStore;
    }

    public Properties allProperties() {
        return this.properties.value();
    }

}
