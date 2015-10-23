package org.bouncycastle.crypto.params;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class SRAKeyGenerationParameters
    extends KeyGenerationParameters
{
    private int certainty;

    public SRAKeyGenerationParameters(
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
    }

    public int getCertainty()
    {
        return certainty;
    }
}
