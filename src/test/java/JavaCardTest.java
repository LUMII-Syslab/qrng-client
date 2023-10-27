import lv.lumii.smartcard.JavaCardCommunication;
import lv.lumii.pqc.InjectablePQC;
import lv.lumii.qrng.clienttoken.FileToken;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;

import java.io.File;
import java.security.Key;
import java.security.SecureRandom;
import java.security.cert.Certificate;

public class JavaCardTest {
  public static void main(String[] args) {
    try {
      JavaCardCommunication comm=new JavaCardCommunication("*");//"5422CL");
      if (!comm.isConnected()) throw new IllegalStateException("FAILED to create a communication with the card");
      byte[] appledID=new byte[] { (byte) 0xa0, (byte) 0xb0, (byte) 0xc0, (byte) 0xd0, (byte) 0xe0 };
      boolean b=comm.selectApplet(appledID);
      if (!b) throw new IllegalStateException("FAILED to create a communication with the card");
      System.out.println("SUCCESSFULLY connected to the applet!");

      System.out.println("~~~ Let's get the PUBLIC KEY! ~~~");
      byte[] pubKey=comm.getPublicKey();
      System.out.println("PUBLIC KEY received: "+bytesToHex(pubKey));

      System.out.println("~~~ Let's get the CERTIFICATE! ~~~");
      byte[] cert=comm.getCertificate();
      System.out.println("CERTIFICATE received: "+bytesToHex(cert));

      FileToken ft = new FileToken(
              new File("/home/sergejs/quantum.gits/qrng-client"+File.separator+"sc.pfx").toString(),
              "client-keystore-pass", // token-pass
              "client" // qrng_user
      );
      Certificate[] chain = ft.certificateChain();
      System.out.println(bytesToHex(chain[0].getEncoded()));
      //System.out.println(bytesToHex(chain[1].getEncoded())); // self-signed ca?


      System.out.println("~~~ Let's SIGN some message! ~~~");
      String msg = "Hello, World!";
      System.out.println("Message to sign: "+msg);
      byte[] signedMsg=comm.sign(msg.getBytes());
      System.out.println("SIGNATURE received: "+bytesToHex(signedMsg));

      // sign manually:
      Key k = ft.key();
      byte[] ke = k.getEncoded();
      System.out.println("PK: "+bytesToHex(ke));
      ASN1Sequence seq0 = ASN1Sequence.getInstance(ke);

      ASN1OctetString octetString = ASN1OctetString.getInstance(seq0.getObjectAt(2));
      ASN1Sequence seq = ASN1Sequence.getInstance(octetString.getOctets());
      ASN1Integer modulus = (ASN1Integer) seq.getObjectAt(1).toASN1Primitive();
      ASN1Integer privateExponent = (ASN1Integer) seq.getObjectAt(3).toASN1Primitive();

      RSAKeyParameters rsaSk = new RSAKeyParameters(true, modulus.getValue(), privateExponent.getValue());

      Digest digest = new SHA256Digest();


      PSSSigner pssSigner = new PSSSigner(new RSAEngine(), digest, 32); // OURS TLS
      pssSigner.init(true, new ParametersWithRandom(rsaSk, new SecureRandom()));

      // Update the signer with the data to be signed
      pssSigner.update(msg.getBytes(), 0, msg.getBytes().length);
      byte[] pssSignatureBytes = pssSigner.generateSignature();

      RSADigestSigner signer = new RSADigestSigner(digest); // ER

      signer.init(true, new ParametersWithRandom(rsaSk, new SecureRandom()));

      // Update the signer with the data to be signed
      signer.update(msg.getBytes(), 0, msg.getBytes().length);
      byte[] signatureBytes = signer.generateSignature();

      System.out.println("MANUALLY SIGNED (PSS ): "+bytesToHex(pssSignatureBytes));

      PSSSigner pssVerifier = new PSSSigner(new RSAEngine(), digest, 32); // OURS TLS
      ASN1Sequence pkSeq = ASN1Sequence.getInstance(pubKey);

      ASN1BitString bitStr = (ASN1BitString) pkSeq.getObjectAt(1);
      ASN1Sequence seq2 = ASN1Sequence.getInstance(bitStr.getOctets());

      ASN1Integer pkModulus = (ASN1Integer) seq2.getObjectAt(0).toASN1Primitive();
      ASN1Integer publicExponent = (ASN1Integer) seq2.getObjectAt(1).toASN1Primitive();

      RSAKeyParameters rsaPk = new RSAKeyParameters(false, pkModulus.getValue(), publicExponent.getValue());

      pssVerifier.init(false, rsaPk);
      pssVerifier.update(msg.getBytes(), 0, msg.getBytes().length);
      String ER = "57956B7028E708923F65146CFE60BA412D3129B6C137EA81B98122B6AB3BF7ACFAE34F550A074CFCB442DE2DA3905580BEBE59108078D2E0A666F5C1A2B205D8022252FEF437EE04658E0EB9689A344CDD422720F50C6F0D33DE4970A33368B24B9CB124738659C2B007AB97D3CD207965ACD9D7E55094291C7F7E411F4588C9F542CC7D5EED6D45467E68353AA4D290C0A89B87909D9CC08BADD352DCD4F57D5777173250579EC6B53E5F3CD6C155B5460355A7456FD2032BF4F7B1CE7658D497FF841AA8DC57F8E0D76E1FB2A94762B9E73906B97D3DBACC2757DEA76D4C477A06066C7D4B7EEB5331D3238D118D00D9F91264C30E5327CD802746928FE2F7";
      pssSignatureBytes = InjectablePQC.hexStringToByteArray(ER);
      System.out.println("VERIFIED (PSS)" + pssVerifier.verifySignature(pssSignatureBytes));

      System.out.println("MANUALLY SIGNED: "+bytesToHex(signatureBytes));



      /////

      System.out.println("~~~ Let's VERIFY some message! ~~~");
      msg = "Hello, World!";
      System.out.println("Message to verify: "+msg);
      System.out.println("Signature to verify the message against: "+bytesToHex(signedMsg));
      b=comm.verify(msg.getBytes(),signedMsg);
      System.out.println("Message verification result: "+b);

      comm.disconnect();
    }
    catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static void printArray(byte[] bytes) {
    for (byte b : bytes) System.out.println(b);
    System.out.println();
  }

  private static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) sb.append(String.format("%02X ", b));
    return sb.toString();
  }
}
