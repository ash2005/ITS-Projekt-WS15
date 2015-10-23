package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class SRAKeyParameters
    extends AsymmetricKeyParameter
{
    private BigInteger      modulus;

    public SRAKeyParameters(
        boolean     isPrivate,
        BigInteger  modulus)
    {
        super(isPrivate);

        this.modulus = modulus;
    }   

    public BigInteger getModulus()
    {
        return modulus;
    }
}
