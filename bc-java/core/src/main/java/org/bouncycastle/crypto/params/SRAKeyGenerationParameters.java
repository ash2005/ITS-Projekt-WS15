package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class SRAKeyGenerationParameters
    extends KeyGenerationParameters
{
    private int certainty;
    private BigInteger p;
    private BigInteger q;

    public SRAKeyGenerationParameters(
        BigInteger      p,
        BigInteger      q,
        SecureRandom    random,
        int             strength,
        int             certainty)
    {
        super(random, strength);

        if (strength < 12)
        {
            throw new IllegalArgumentException("key strength too small");
        }
        
        if (p != null && q == null) {
        	throw new IllegalArgumentException("second prime is missing");
        }
        else if (p == null && q != null) {
        	throw new IllegalArgumentException("first prime is missing");
        }
        
        this.certainty = certainty;
        this.p = p;
        this.q = q;
    }

    public BigInteger getP()
    {
        return p;
    }
    public BigInteger getQ()
    {
        return q;
    }
    public int getCertainty()
    {
        return certainty;
    }
}
