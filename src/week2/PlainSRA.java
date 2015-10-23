package week2;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.crypto.generators.SRAKeyPairGenerator;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SRAKeyParameters;
import org.bouncycastle.util.encoders.Hex;

public class PlainSRA {
	
	public static byte[] encrypt(AsymmetricCipherKeyPair keypair, byte[] input) {
		byte[] encrData = null;
		
		AsymmetricBlockCipher engEn = new SRAEngine();
		engEn.init(true, keypair.getPrivate());

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
		SRAKeyPairGenerator keygen = new SRAKeyPairGenerator();
		keygen.init(new SRAKeyGenerationParameters(
				null,
				new SecureRandom(), // prng
				1024, // strength
				80// certainty
		));

		AsymmetricCipherKeyPair keypair1 = keygen.generateKeyPair();
		
		SRAKeyParameters x = (SRAKeyParameters)keypair1.getPublic();
		
		keygen.init(new SRAKeyGenerationParameters(
				x.getModulus(),
				new SecureRandom(), // prng
				1024, // strength
				80// certainty
		));
		
		AsymmetricCipherKeyPair keypair2 = keygen.generateKeyPair();
		
		
		encrData1 = encrypt(keypair1, data);
		encrData1 = encrypt(keypair2, encrData1);
		
		decrData1 = decrypt(keypair2, encrData1);
		decrData1 = decrypt(keypair1, decrData1);
		
		String text0 = Hex.toHexString(data);
		//String text1 = Hex.toHexString(encrData);
		String text2 = Hex.toHexString(decrData1);

		//System.out.println("Input: " + text0 + "\n" + "Encr:  " + text1 + "\n" + "Decr: " + text2);

		if (text0.equals(text2)) {
			System.out.println("Success");
		} else {
			System.out.println("Fail");
		}

	}

}
