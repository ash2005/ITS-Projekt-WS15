package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class _SRAKeyParameters
    extends AsymmetricKeyParameter
{
    private BigInteger      modulus;

    public _SRAKeyParameters(
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
