package org.bouncycastle.pqc.jcajce.provider.sphincsplus;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class SPHINCSPlusKeyFactorySpi
    extends KeyFactorySpi
    implements AsymmetricKeyInfoConverter
{
    public PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            // get the DER-encoded Key according to PKCS#8 from the spec
            byte[] encKey = ((PKCS8EncodedKeySpec)keySpec).getEncoded();

            try
            {
                return generatePrivate(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey)));
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException(e.toString());
            }
        }

        throw new InvalidKeySpecException("Unsupported key specification: "
            + keySpec.getClass() + ".");
    }

    public PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            // get the DER-encoded Key according to X.509 from the spec
            byte[] encKey = ((X509EncodedKeySpec)keySpec).getEncoded();
            for (int i=0; i< encKey.length; i++)
                System.out.printf("%02X ", encKey[i]>=0?encKey[i]:256+encKey[i]);
            System.out.println();
/* ASN.1: SEQUENCE (2 elem)
  SEQUENCE (2 elem)
    OBJECT IDENTIFIER 1.3.9999.6.7.1
    NULL
  BIT STRING (256 bit) 0001011010101111001101001101001010100000100001010100001010100110111111…
  in HEX: 30 2F 30 0A 06 06 2B CE 0F 06 07 01 05 00 03 21 00 16 AF 34 D2 A0 85 42 A6 FC D8 B9 CE AB 9E A4 FA 4B F6 40 A5 CD 86 6F 87 AA D1 6A 97 16 03 E1 73
 */
            //encKey = Arrays.copyOfRange( encKey, 14+2+1, encKey.length); // for our sphincs+ by SK

            // decode the SubjectPublicKeyInfo data structure to the pki object
            try
            {
                return generatePublic(SubjectPublicKeyInfo.getInstance(encKey));
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException(e.toString());
            }
        }

        throw new InvalidKeySpecException("Unknown key specification: " + keySpec + ".");
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCSPHINCSPlusPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCSPHINCSPlusPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new X509EncodedKeySpec(key.getEncoded());
            }
        }
        else
        {
            throw new InvalidKeySpecException("Unsupported key type: "
                + key.getClass() + ".");
        }

        throw new InvalidKeySpecException("Unknown key specification: "
            + keySpec + ".");
    }

    public final Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCSPHINCSPlusPrivateKey || key instanceof BCSPHINCSPlusPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCSPHINCSPlusPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCSPHINCSPlusPublicKey(keyInfo);
    }
}
