package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class SRAKeyGenerationParameters
    extends KeyGenerationParameters
{
    private int certainty;
    private BigInteger modulus;

    public SRAKeyGenerationParameters(
    	BigInteger      modulus,
    	SecureRandom    random,
        int             strength,
        int             certainty)
    {
        super(random, strength);

        if (strength < 12)
        {
            throw new IllegalArgumentException("key strength too small");
        }
        
        this.certainty = certainty;
        this.modulus = modulus;
    }

    public BigInteger getModulus()
    {
        return modulus;
    }
    
    public int getCertainty()
    {
        return certainty;
    }
}
