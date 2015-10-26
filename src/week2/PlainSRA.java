package week2;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.crypto.generators.SRAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;
import org.bouncycastle.util.encoders.Hex;

public class PlainSRA {
	
	public static byte[] encrypt(AsymmetricCipherKeyPair keypair, byte[] input) {
		byte[] encrData = null;
		
		AsymmetricBlockCipher engEn = new SRAEngine();
		engEn.init(true, keypair.getPublic());

		try {
			encrData = engEn.processBlock(input, 0, input.length);
		} catch (InvalidCipherTextException error) {
			error.printStackTrace();
		}
		
		return encrData;
	}
	
	public static byte[] decrypt(AsymmetricCipherKeyPair keypair, byte[] input) {
		byte[] decrData = null;
		
		AsymmetricBlockCipher engDe = new SRAEngine();
		engDe.init(false, keypair.getPrivate());

		try {
			decrData = engDe.processBlock(input, 0, input.length);
		} catch (InvalidCipherTextException error) {
			error.printStackTrace();
		}
		return decrData;
	}
	
	public static void main(String[] args) {
		// data
		String input = "Test";
		byte[] data = input.getBytes();
		byte[] encrData1 = null;
		byte[] decrData1 = null;

		System.out.println("Text: " + input + " Länge: " + data.length);

		// Create Keys
		SRAKeyPairGenerator keygen1 = new SRAKeyPairGenerator();
		keygen1.init(new SRAKeyGenerationParameters(
				null,
				null,
				new SecureRandom(), // prng
				1024, // strength
				80// certainty
		));

		AsymmetricCipherKeyPair keypair1 = keygen1.generateKeyPair();
		
		SRAKeyPairGenerator keygen2 = new SRAKeyPairGenerator();
		keygen2.init(new SRAKeyGenerationParameters(
				((RSAPrivateCrtKeyParameters)keypair1.getPrivate()).getP(),
				((RSAPrivateCrtKeyParameters)keypair1.getPrivate()).getQ(),
				new SecureRandom(), // prng
				1024, // strength
				80// certainty
		));
		
		AsymmetricCipherKeyPair keypair2 = keygen2.generateKeyPair();
		
		
		System.out.println("Key1:\n" +
				"N: " + ((RSAPrivateCrtKeyParameters)keypair1.getPrivate()).getModulus() + "\n" +
				"E: " + ((RSAPrivateCrtKeyParameters)keypair1.getPrivate()).getExponent() + "\n" +
				"P: " + ((RSAPrivateCrtKeyParameters)keypair1.getPrivate()).getP() + "\n" +
				"Q: " + ((RSAPrivateCrtKeyParameters)keypair1.getPrivate()).getQ() + "\n"
		);
		
		System.out.println("Key2:\n" +
				"N: " + ((RSAPrivateCrtKeyParameters)keypair2.getPrivate()).getModulus() + "\n" +
				"E: " + ((RSAPrivateCrtKeyParameters)keypair2.getPrivate()).getExponent() + "\n" +
				"P: " + ((RSAPrivateCrtKeyParameters)keypair2.getPrivate()).getP() + "\n" +
				"Q: " + ((RSAPrivateCrtKeyParameters)keypair2.getPrivate()).getQ() + "\n"
		);
		
		encrData1 = encrypt(keypair1, data);
		encrData1 = encrypt(keypair2, encrData1);
		
		decrData1 = decrypt(keypair1, encrData1);
		decrData1 = decrypt(keypair2, decrData1);
		
		String text0 = Hex.toHexString(data);
		//String text1 = Hex.toHexString(encrData);
		String text2 = Hex.toHexString(decrData1);

		//System.out.println("Input: " + text0 + "\n" + "Encr:  " + text1 + "\n" + "Decr: " + text2);
		
		try {
			System.out.println(new String(decrData1, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		if (text0.equals(text2)) {
			System.out.println("Success");
		} else {
			System.out.println("Fail");
		}

	}

}
