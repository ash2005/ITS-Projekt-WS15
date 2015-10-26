package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.crypto.generators.SRAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class SRATest
    extends SimpleTest
{
	static String input = "4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";
	
    public String getName()
    {
        return "SRA";
    }

    public void performTest()
    {
    	byte[] data = Hex.decode(input);
    	
    	AsymmetricBlockCipher   eng = new SRAEngine();
    	
        //
        // commutative test
        //
        SRAKeyPairGenerator  pGen = new SRAKeyPairGenerator();
        SRAKeyGenerationParameters  genParam = new SRAKeyGenerationParameters(
                                            null, null, new SecureRandom(), 1024, 80);

        pGen.init(genParam);

        AsymmetricCipherKeyPair  pair1 = pGen.generateKeyPair();
        
        genParam = new SRAKeyGenerationParameters(
        		((RSAPrivateCrtKeyParameters)pair1.getPrivate()).getP(),
        		((RSAPrivateCrtKeyParameters)pair1.getPrivate()).getQ(),
        		new SecureRandom(), 1024, 80);
        
        pGen.init(genParam);
                
        AsymmetricCipherKeyPair  pair2 = pGen.generateKeyPair();
        
        eng = new SRAEngine();

        eng.init(true, pair1.getPublic());

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }
        
        eng.init(true, pair2.getPublic());

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        eng.init(false, pair1.getPrivate());

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }
        
        eng.init(false, pair2.getPrivate());

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        if (!input.equals(new String(Hex.encode(data))))
        {
            System.out.println("Key1:\n" +
    				"N: " + ((RSAPrivateCrtKeyParameters)pair1.getPrivate()).getModulus() + "\n" +
    				"E: " + ((RSAPrivateCrtKeyParameters)pair1.getPrivate()).getExponent() + "\n" +
    				"P: " + ((RSAPrivateCrtKeyParameters)pair1.getPrivate()).getP() + "\n" +
    				"Q: " + ((RSAPrivateCrtKeyParameters)pair1.getPrivate()).getQ() + "\n"
    		);
    		
    		System.out.println("Key2:\n" +
    				"N: " + ((RSAPrivateCrtKeyParameters)pair2.getPrivate()).getModulus() + "\n" +
    				"E: " + ((RSAPrivateCrtKeyParameters)pair2.getPrivate()).getExponent() + "\n" +
    				"P: " + ((RSAPrivateCrtKeyParameters)pair2.getPrivate()).getP() + "\n" +
    				"Q: " + ((RSAPrivateCrtKeyParameters)pair2.getPrivate()).getQ() + "\n"
    		);
    		
    		fail("commutative test fails");
            
        }
    }


    public static void main(
        String[]    args)
    {
    	runTest(new RSATest());
    	runTest(new SRATest());
    }
}
