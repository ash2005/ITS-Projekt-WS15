package org.bouncycastle.crypto.generators;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SRAKeyParameters;
import org.bouncycastle.crypto.params.SRAPrivateCrtKeyParameters;

/**
 * an SRA key pair generator.
 */
public class SRAKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{

    private SRAKeyGenerationParameters param;
    private static final BigInteger ONE = BigInteger.valueOf(1);
    
    public void init(KeyGenerationParameters param)
    {
        this.param = (SRAKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
    	
    	AsymmetricCipherKeyPair result = null;
    	
    	int strength = param.getStrength();
    	int nbitlength = (strength + 1) / 2;
    	
    	BigInteger n = chooseRandomPrime(nbitlength);
    	
    	BigInteger e = chooseRandomPrime(nbitlength);
    	
    	
    	BigInteger d = e.modInverse(n.subtract(ONE) );
    	
    	result = new AsymmetricCipherKeyPair(
              new SRAKeyParameters(false, n),
              new SRAPrivateCrtKeyParameters(n, e, d));
    	
    	return result;
    	
    	
//        AsymmetricCipherKeyPair result = null;
//        boolean done = false;
//
//        //
//        // p and q values should have a length of half the strength in bits
//        //
//        int strength = param.getStrength();
//        int pbitlength = (strength + 1) / 2;
//        int qbitlength = strength - pbitlength;
//        int mindiffbits = strength / 3;
//        int minWeight = strength >> 2;
//
//        // d lower bound is 2^(strength / 2)
//        BigInteger dLowerBound = BigInteger.valueOf(2).pow(strength / 2);
//
//        while (!done)
//        {
//            BigInteger p, q, n, d, e, pSub1, qSub1, gcd, lcm;
//
//            e = param.getPublicExponent();
//
//            // TODO Consider generating safe primes for p, q (see DHParametersHelper.generateSafePrimes)
//            // (then p-1 and q-1 will not consist of only small factors - see "Pollard's algorithm")
//
//            p = chooseRandomPrime(pbitlength, e);
//
//            //
//            // generate a modulus of the required length
//            //
//            for (; ; )
//            {
//                q = chooseRandomPrime(qbitlength, e);
//
//                // p and q should not be too close together (or equal!)
//                BigInteger diff = q.subtract(p).abs();
//                if (diff.bitLength() < mindiffbits)
//                {
//                    continue;
//                }
//
//                //
//                // calculate the modulus
//                //
//                n = p.multiply(q);
//
//                if (n.bitLength() != strength)
//                {
//                    //
//                    // if we get here our primes aren't big enough, make the largest
//                    // of the two p and try again
//                    //
//                    p = p.max(q);
//                    continue;
//                }
//
//	            /*
//                 * Require a minimum weight of the NAF representation, since low-weight composites may
//	             * be weak against a version of the number-field-sieve for factoring.
//	             *
//	             * See "The number field sieve for integers of low weight", Oliver Schirokauer.
//	             */
//                if (WNafUtil.getNafWeight(n) < minWeight)
//                {
//                    p = chooseRandomPrime(pbitlength, e);
//                    continue;
//                }
//
//                break;
//            }
//
//            if (p.compareTo(q) < 0)
//            {
//                gcd = p;
//                p = q;
//                q = gcd;
//            }
//
//            pSub1 = p.subtract(ONE);
//            qSub1 = q.subtract(ONE);
//            gcd = pSub1.gcd(qSub1);
//            lcm = pSub1.divide(gcd).multiply(qSub1);
//
//            //
//            // calculate the private exponent
//            //
//            d = e.modInverse(lcm);
//
//            if (d.compareTo(dLowerBound) <= 0)
//            {
//                continue;
//            }
//            else
//            {
//                done = true;
//            }
//
//            //
//            // calculate the CRT factors
//            //
//            BigInteger dP, dQ, qInv;
//
//            dP = d.remainder(pSub1);
//            dQ = d.remainder(qSub1);
//            qInv = q.modInverse(p);
//
//            result = new AsymmetricCipherKeyPair(
//                new RSAKeyParameters(false, n, e),
//                new RSAPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv));
//        }
//
//        return result;
    }

    /**
     * Choose a random prime value for use with RSA
     * 
     * @param bitlength the bit-length of the returned prime
     * @param e the RSA public exponent
     * @return a prime p, with (p-1) relatively prime to e
     */
    protected BigInteger chooseRandomPrime(int bitlength)
    {
        for (;;)
        {
            BigInteger p = new BigInteger(bitlength, 1, param.getRandom());
            
            if (!p.isProbablePrime(param.getCertainty()))
            {
                continue;
            }
            
            return p;
        }
    }
}
