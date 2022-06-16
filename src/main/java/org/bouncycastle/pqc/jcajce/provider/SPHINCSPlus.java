package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;

public class SPHINCSPlus
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".sphincsplus.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.SPHINCSPLUS", PREFIX + "SPHINCSPlusKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SPHINCSPLUS", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.SPHINCS+", "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.SPHINCS+", "SPHINCSPLUS");

            addSignatureAlgorithm(provider, "SPHINCSPLUS", PREFIX + "SignatureSpi$Direct", BCObjectIdentifiers.sphincsPlus); // replaced by SK2
            //addSignatureAlgorithm(provider, "SPHINCSPLUS", PREFIX + "SignatureSpi$Direct", PQCObjectIdentifiers.oqs_sphincsshake256128frobust); // by SK2
            //addSignatureAlgorithm(provider, "SHAKE", PREFIX + "SignatureSpi$Direct", PQCObjectIdentifiers.oqs_sphincsshake256128frobust); // by SK2
            //addSignatureAlgorithm(provider, "SHAKE256", PREFIX + "SignatureSpi$Direct", PQCObjectIdentifiers.oqs_sphincsshake256128frobust); // by SK2


            provider.addAlgorithm("Alg.Alias.Signature." + BCObjectIdentifiers.sphincsPlus_shake_256.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature." + BCObjectIdentifiers.sphincsPlus_sha_256.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature." + BCObjectIdentifiers.sphincsPlus_sha_512.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + BCObjectIdentifiers.sphincsPlus_shake_256.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + BCObjectIdentifiers.sphincsPlus_sha_256.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + BCObjectIdentifiers.sphincsPlus_sha_512.getId(), "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.Signature."+PQCObjectIdentifiers.oqs_sphincsshake256128frobust, "SPHINCSPLUS"); // by SK2
            provider.addAlgorithm("Alg.Alias.Signature.OID."+PQCObjectIdentifiers.oqs_sphincsshake256128frobust, "SPHINCSPLUS"); // by SK2

            provider.addAlgorithm("Alg.Alias.Signature.SPHINCS+", "SPHINCSPLUS");

            AsymmetricKeyInfoConverter keyFact = new SPHINCSPlusKeyFactorySpi();

            registerOid(provider, PQCObjectIdentifiers.oqs_sphincsshake256128frobust, "SPHINCSPLUS", keyFact); // by SK2++
            registerOid(provider, BCObjectIdentifiers.sphincsPlus, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha_256, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha_512, "SPHINCSPLUS", keyFact);
            registerOidAlgorithmParameters(provider, BCObjectIdentifiers.sphincsPlus, "SPHINCSPLUS");
            registerOidAlgorithmParameters(provider, PQCObjectIdentifiers.oqs_sphincsshake256128frobust, "SPHINCSPLUS"); // by SK2++

            provider.addKeyInfoConverter(PQCObjectIdentifiers.oqs_sphincsshake256128frobust, keyFact); // by SK2++
        }
    }
}
