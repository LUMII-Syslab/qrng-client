package lv.lumii.smartcard;

import lv.lumii.pqc.InjectablePQC;
import lv.lumii.qrng.ClientTokenFactory;
import lv.lumii.qrng.QrngProperties;
import lv.lumii.qrng.clienttoken.SmartCardToken;
import lv.lumii.qrng.clienttoken.Token;

public class SmartCardClientTokenFactory implements ClientTokenFactory {
    public SmartCardClientTokenFactory(QrngProperties qrngProperties) {
        String scLib = qrngProperties.allProperties().getProperty("smartcardLibrary");
        if (scLib != null)
            System.setProperty("sun.security.smartcardio.library", scLib);
        // Alternatively, you can specify the library in JVM args:
        // -Dsun.security.smartcardio.library=/usr/lib/x86_64-linux-gnu/libpcsclite.so.1
    }

    @Override
    public Token clientToken(String location) {
        // In Linux, for smart cards to work, you need to install these packages and restart pcscd:
        //   sudo apt-get install libccid pcscd libpcsclite-dev libpcsclite1
        //   sudo service pcscd start
        // We also need to add this JVM option:
        //   -Dsun.security.smartcardio.library=/usr/lib/x86_64-linux-gnu/libpcsclite.so.1

        String smartCardReaderName = location;
        JavaCardCommunication comm = new JavaCardCommunication(smartCardReaderName);
        if (!comm.isConnected()) throw new IllegalStateException("FAILED to create a communication with the card");
        byte[] appledID = new byte[]{(byte) 0xa0, (byte) 0xb0, (byte) 0xc0, (byte) 0xd0, (byte) 0xe0};
        boolean b = comm.selectApplet(appledID);
        if (!b) throw new IllegalStateException("FAILED to create a communication with the card");
        System.out.println("SUCCESSFULLY connected to the applet!");

        System.out.println("~~~ Let's get the PUBLIC KEY! ~~~");
        byte[] pubKey = comm.getPublicKey();

        System.out.println("~~~ Let's get the CERTIFICATE!  ~~~");
        byte[] cert = comm.getCertificate();

        //SmartCardToken sct = new SmartCardToken(ft.certificateChain(), ft.key(),
        SmartCardToken sct = new SmartCardToken(cert, //ft.key()/*dummy*/,
                (message) -> { // sign function
                    System.out.println("CARD SIGNATURE");
                    byte[] signed = comm.sign(message);
                    System.out.println("SIGNED: " + InjectablePQC.byteArrayToString(signed, " "));
                    return signed;
                });
        return sct;
    }
}
