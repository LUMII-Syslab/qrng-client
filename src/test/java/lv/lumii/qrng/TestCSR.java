package lv.lumii.qrng;


import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.OutputStream;
import java.security.PrivateKey;

public class TestCSR
{

    public static void main(String[] args) throws Exception
    {

        byte[] csr = InjectablePQC.hexStringToByteArray("30 82 02 8c 30 82 01 74 02 01 00 30 47 31 0b 30 09 06 03 55 04 06 13 02 4c 56 31 0d 30 0b 06 03 55 04 07 0c 04 52 69 67 61 31 10 30 0e 06 03 55 04 0a 0c 07 49 4d 43 53 2c 55 4c 31 17 30 15 06 03 55 04 03 0c 0e 49 4d 43 53 2c 55 4c 20 63 6c 69 65 6e 74 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 ac 5d 4f 62 35 fc a9 91 3e 10 96 ec 03 2f a7 bd 7e b7 0c 64 b1 6a 9d 26 69 1d 06 e4 80 65 30 4a 7f 21 3b 1e 8b a3 7b 45 e5 bf 66 d5 cb 46 3a cc 8e e9 0c 46 07 7a 7b 59 a2 d0 8c 0a 18 40 e7 5c 34 60 3e 4b 64 77 01 dc 27 b4 18 e4 ce 97 5b 23 7f e1 95 90 88 4c 98 db 4b 04 77 e0 96 33 98 4c 51 76 46 b0 7a 7b 66 a7 98 8e 0e a7 9d bc 69 da 52 95 5d 6f a2 3b 9d 53 f6 2d fb 89 cc 54 78 56 b2 2b d3 1c 1e 57 a3 59 74 c2 f6 5e 12 7b ec c3 cf 8f 58 34 01 2b e6 b2 fa 26 7a e0 77 c5 97 bb 4d fe 72 0d f6 dd 55 92 1b f9 3f 8d 9c e5 e5 24 a8 b6 22 fe c4 28 da f2 08 c7 a1 ba c6 7f 53 f6 a9 ce 63 44 c5 93 d7 92 ee f5 72 66 2a ab 80 2f 6b 68 ca 9a de ad 36 1d a1 0b c2 12 ae cd 4c f3 81 97 08 25 67 dd 8e 03 c9 24 1b 59 04 1c f2 07 f5 0e 2c 74 d4 fa 55 42 cb 88 5c 1f 80 28 1b a1 02 03 01 00 01 a0 00 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 16 fa 93 3c e0 34 68 80 fb 20 90 9e af fb 5a ab e3 a4 9d e4 80 27 e2 17 8d 0b 8d b3 66 22 c2 db fa bd 6f 7e ed b7 da e5 3b bf cc 6e 86 e8 a0 d0 27 cc 52 00 94 5e 35 e5 76 e2 69 7b c4 0d b8 f1 ab 4f a5 50 95 08 d3 1f 9e fa a1 3a 65 82 27 ae 34 9a b7 85 f2 87 c6 d8 42 b8 91 20 a3 06 58 57 bd f8 26 36 10 8a f5 d6 60 f9 a2 3e cc c9 f6 a0 84 07 25 8a 00 cd 12 d7 06 21 75 4b 91 84 19 f1 33 49 69 c7 d8 e1 b6 fa cd 3a f0 10 ca c7 b1 a4 7d d9 08 59 6d dd 46 de 73 ac fd da 8a 94 bf 5c 6e 79 16 03 22 df 85 97 02 17 78 c7 a7 39 3e bc 5d b3 a4 be 04 25 36 8f 2e 82 1f bb e4 5b b0 df e5 18 b5 29 7c ec 39 7a 03 5e 3d 4d 17 38 bb 42 7e 05 8d 88 a6 a7 de 2e 90 7c 9e 35 4a 6c e7 bf 97 aa 57 c3 6b 80 09 2e 0f 57 16 3b c3 9f c6 38 b9 21 2a 5a 03 a5 fc 43 e5 9f 39 02 85 94 d8 ca");
        byte[] privateKey = InjectablePQC.hexStringToByteArray("30 82 04 be 02 01 00 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 04 82 04 a8 30 82 04 a4 02 01 00 02 82 01 01 00 ac 5d 4f 62 35 fc a9 91 3e 10 96 ec 03 2f a7 bd 7e b7 0c 64 b1 6a 9d 26 69 1d 06 e4 80 65 30 4a 7f 21 3b 1e 8b a3 7b 45 e5 bf 66 d5 cb 46 3a cc 8e e9 0c 46 07 7a 7b 59 a2 d0 8c 0a 18 40 e7 5c 34 60 3e 4b 64 77 01 dc 27 b4 18 e4 ce 97 5b 23 7f e1 95 90 88 4c 98 db 4b 04 77 e0 96 33 98 4c 51 76 46 b0 7a 7b 66 a7 98 8e 0e a7 9d bc 69 da 52 95 5d 6f a2 3b 9d 53 f6 2d fb 89 cc 54 78 56 b2 2b d3 1c 1e 57 a3 59 74 c2 f6 5e 12 7b ec c3 cf 8f 58 34 01 2b e6 b2 fa 26 7a e0 77 c5 97 bb 4d fe 72 0d f6 dd 55 92 1b f9 3f 8d 9c e5 e5 24 a8 b6 22 fe c4 28 da f2 08 c7 a1 ba c6 7f 53 f6 a9 ce 63 44 c5 93 d7 92 ee f5 72 66 2a ab 80 2f 6b 68 ca 9a de ad 36 1d a1 0b c2 12 ae cd 4c f3 81 97 08 25 67 dd 8e 03 c9 24 1b 59 04 1c f2 07 f5 0e 2c 74 d4 fa 55 42 cb 88 5c 1f 80 28 1b a1 02 03 01 00 01 02 82 01 00 77 b2 08 b9 93 f2 14 b3 27 1d 90 20 ef 89 7d 7b eb 6e 24 6e 1c 82 84 05 33 83 93 d0 c4 95 00 77 0b 57 c1 5d 51 ed 42 62 e4 cc 09 16 b8 a5 d9 99 4a 38 ee 6c 07 2f 78 4f 63 f0 5c ff 79 9e 40 cc 58 16 e9 cb a3 45 bd 85 ec 10 76 25 16 8e 27 1d 3c e6 23 de 0d b8 db 81 95 d3 d1 87 a5 e6 c8 81 5f 24 ba ac 3d 32 4a b4 62 0d 6c 81 db d9 06 cd 35 02 42 b3 8e 3e c5 df 93 9a 95 0e 39 56 03 86 55 2c eb 40 f3 b9 47 48 f9 f0 dc 5b bd 7d 8e 46 49 cb 34 14 39 af 11 a4 c9 f9 7f f6 c3 7d 2d 9c d9 4d bc 3e 9f 55 af 51 f3 e6 4f 61 d1 e0 eb 0e b9 6e 6c 20 6a df b8 e6 9f 50 97 90 51 69 26 15 0c fb bb 90 a8 60 96 83 1a 25 e5 ee bb 00 23 eb 04 dd 6f 7c 9a 61 cb f2 68 38 35 1b fd 72 0f ae 3b d0 9c 32 54 87 42 10 8d 9c e8 07 fa 31 47 25 ba 36 8a a7 84 eb 0b 5b 35 cb e8 8a 59 5f bd 0d 02 81 81 00 d8 75 db 2f 10 c1 80 63 46 32 33 2e f2 df 32 21 56 ac ee ed e7 27 57 7e 8b 60 3e 8d b5 39 81 8d 6b 52 ac 71 dc 57 41 d6 8d 59 5e 69 c1 33 e9 4d b7 cf 75 c6 fb 3d c5 3f cc 03 54 0e b1 f9 18 d4 22 8e ec 61 ae 7c b9 7e 26 b5 b4 cc cf 7b d9 df f5 27 c7 0d eb 03 c7 3a b4 18 23 a1 d4 03 88 42 57 b2 fd c4 f4 4a 0a 72 9c f0 a6 f5 8f 79 d7 32 78 18 68 cf 51 a0 9c 06 90 4b ae f7 e2 4d c2 db 02 81 81 00 cb d9 6f f8 5a 96 03 44 d5 cf 2e 78 e2 98 95 b0 c0 f4 77 de 4b 18 2a 95 da be af ed 55 31 0f e5 5c d3 7c af 62 05 84 f3 07 9f 6a a7 6f e1 d0 48 11 8c 3e ea fc 8c ad 00 65 4e 19 9c fa 26 d2 86 7e e5 5f 00 45 e9 5a 5f 2f aa 34 6d f7 18 69 c5 ea 29 12 63 a0 25 20 17 10 1a c1 82 fe 00 1d d3 08 e0 e2 84 ac 27 a9 86 96 94 23 ae 73 e1 c6 dd 1b a5 50 e8 3b d9 06 ff e9 db f9 91 b1 8f fe 33 02 81 81 00 9a 11 b1 13 db f2 4e e6 da 54 ea d7 74 e9 66 ae 12 1a 7e e9 f8 88 a9 1f 1a 27 43 fe eb 49 e6 2b 79 83 5b d8 a3 43 bc 49 f1 4b f6 06 82 0c e7 f7 78 68 82 e5 41 78 a3 08 18 b7 19 c2 67 ec ec 3e 39 e6 ce db 6c 2d bc 7d cd 21 b2 71 c1 10 df 70 27 f7 cb 17 dd fa 4f 79 3a 2c a0 58 14 26 fb 7a 75 1f a2 be e8 3e 37 17 83 1b 4b 4b 27 77 4a b3 d2 85 55 3c 93 56 25 18 0a e6 c3 c0 0e 64 d8 d7 02 81 80 4d 90 b2 0b 55 24 a9 9f c2 9f 6f f6 6d 7a 53 d3 0a c8 ba e7 a9 b9 4b 52 f4 06 04 d9 10 c6 77 5e f5 e0 3f 1c 58 f6 f2 ac aa e4 dc e7 53 2a 20 5f 9b d5 ba 87 1d 8b c5 b4 55 d7 ce e5 2d 46 22 6b 2c d3 c8 3f 49 5a ce 99 53 80 b7 2c 74 8e 24 89 3b 5d 5f 72 eb 17 d5 4b 11 44 ad 07 53 f0 e5 68 4c 83 8d 8d a0 18 03 68 83 d9 60 6e 5c 07 b7 ec a0 3d 5a 38 d3 b4 f3 f5 e2 9d 62 2c 2e dd 34 83 02 81 81 00 bd fa 4a db c1 10 f0 c0 41 c9 64 f5 32 51 bc b2 3b 73 ca d9 5e d0 c8 2f 2a 83 d9 0b d3 62 d5 18 e0 e7 96 9a 03 4f 20 d7 3b 19 67 f4 cc 20 33 d7 3f a4 fb 3c 62 7c d9 95 d3 e8 23 01 79 1d df 18 6f 69 84 df ec ae 3c fb 37 26 97 e9 8a a0 cd c2 3e fd 19 09 9a 24 86 2a d8 ae 0e 8b 9f ca 99 6a 73 72 63 92 83 6c b0 84 ea 87 7d 32 5b 4a 20 e1 ae 2f 3c 60 4f e9 52 66 aa 0b 6f 76 6f fc 51 a2");
        byte[] publicKey = InjectablePQC.hexStringToByteArray("30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 ac 5d 4f 62 35 fc a9 91 3e 10 96 ec 03 2f a7 bd 7e b7 0c 64 b1 6a 9d 26 69 1d 06 e4 80 65 30 4a 7f 21 3b 1e 8b a3 7b 45 e5 bf 66 d5 cb 46 3a cc 8e e9 0c 46 07 7a 7b 59 a2 d0 8c 0a 18 40 e7 5c 34 60 3e 4b 64 77 01 dc 27 b4 18 e4 ce 97 5b 23 7f e1 95 90 88 4c 98 db 4b 04 77 e0 96 33 98 4c 51 76 46 b0 7a 7b 66 a7 98 8e 0e a7 9d bc 69 da 52 95 5d 6f a2 3b 9d 53 f6 2d fb 89 cc 54 78 56 b2 2b d3 1c 1e 57 a3 59 74 c2 f6 5e 12 7b ec c3 cf 8f 58 34 01 2b e6 b2 fa 26 7a e0 77 c5 97 bb 4d fe 72 0d f6 dd 55 92 1b f9 3f 8d 9c e5 e5 24 a8 b6 22 fe c4 28 da f2 08 c7 a1 ba c6 7f 53 f6 a9 ce 63 44 c5 93 d7 92 ee f5 72 66 2a ab 80 2f 6b 68 ca 9a de ad 36 1d a1 0b c2 12 ae cd 4c f3 81 97 08 25 67 dd 8e 03 c9 24 1b 59 04 1c f2 07 f5 0e 2c 74 d4 fa 55 42 cb 88 5c 1f 80 28 1b a1 02 03 01 00 01");

        ASN1Sequence csrSeq = ASN1Sequence.getInstance(csr);
        ASN1Sequence whatToSign = (ASN1Sequence) csrSeq.getObjectAt(0);

        System.out.println(InjectablePQC.byteArrayToString(whatToSign.getEncoded(), " "));

        CertificationRequestInfo info = CertificationRequestInfo.getInstance(whatToSign);

        PrivateKeyInfo sk = PrivateKeyInfo.getInstance(privateKey);
        SubjectPublicKeyInfo pk = SubjectPublicKeyInfo.getInstance(publicKey);

        /*ASN1OctetString octetString = ASN1OctetString.getInstance(privateKey);
        ASN1Sequence seq = ASN1Sequence.getInstance(octetString.getOctets());
        ASN1Integer modulus = (ASN1Integer) seq.getObjectAt(1).toASN1Primitive();
        ASN1Integer privateExponent = (ASN1Integer) seq.getObjectAt(3).toASN1Primitive();

        RSAKeyParameters rsaSk = new RSAKeyParameters(true, modulus.getValue(), privateExponent.getValue());
*/
        org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter converter = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter();
        PrivateKey privateKey2 = converter.getPrivateKey(sk);

        org.bouncycastle.operator.ContentSigner contentSigner = null;
        try
        {
            contentSigner = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privateKey2);
        } catch (Exception e)
        {
            //e.printStackTrace();
            throw new RuntimeException(e);
        }

        OutputStream sOut = contentSigner.getOutputStream();

        sOut.write(whatToSign.getEncoded());

        sOut.close();


        PKCS10CertificationRequest signedCSR = new PKCS10CertificationRequest(new CertificationRequest(info, contentSigner.getAlgorithmIdentifier(), new DERBitString(contentSigner.getSignature())));

        System.out.println("SIGNED CSR");
        System.out.println(InjectablePQC.byteArrayToString(signedCSR.getEncoded(), " "));


        //PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(new X500Name(subjectName), pk);
    }


}
