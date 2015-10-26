package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class _SRAPrivateCrtKeyParameters
    extends _SRAKeyParameters
{
    private BigInteger  e;
    private BigInteger  d;
    /**
     * 
     */
    public _SRAPrivateCrtKeyParameters(
        BigInteger  modulus,
        BigInteger  publicExponent,
        BigInteger  privateExponent)
    {
        super(true, modulus);

        this.e = publicExponent;
        this.d = privateExponent;
    }

    public BigInteger getPublicExponent()
    {
        return e;
    }

    public BigInteger getPrivateExponent()
    {
        return d;
    }
}
