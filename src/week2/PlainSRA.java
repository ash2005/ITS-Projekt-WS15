package week2;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.crypto.generators.SRAKeyPairGenerator;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;
import org.bouncycastle.util.encoders.Hex;

public class PlainSRA {

	public static void main(String[] args) {
		// data
		String input = "Test";
		byte[] data = input.getBytes();
		byte[] encrData = null;
		byte[] decrData = null;

		System.out.println("Text: " + input + " Länge: " + data.length);

		// Create Keys
		SRAKeyPairGenerator keygen = new SRAKeyPairGenerator();
		keygen.init(new SRAKeyGenerationParameters(
				new SecureRandom(), // prng
				2048, // strength
				80// certainty
		));

		AsymmetricCipherKeyPair keypair = keygen.generateKeyPair();
		
		// Encryption
		AsymmetricBlockCipher engEn = new SRAEngine();
		engEn.init(true, keypair.getPrivate());

		// System.out.println(engEn.getInputBlockSize());
		// System.out.println(engEn.getOutputBlockSize());

		try {
			encrData = engEn.processBlock(data, 0, data.length);
		} catch (InvalidCipherTextException error) {
			error.printStackTrace();
		}

		// Decryption
		AsymmetricBlockCipher engDe = new SRAEngine();
		engDe.init(false, keypair.getPrivate());

		try {
			decrData = engDe.processBlock(encrData, 0, encrData.length);
		} catch (InvalidCipherTextException error) {
			error.printStackTrace();
		}

		String text0 = Hex.toHexString(data);
		String text1 = Hex.toHexString(encrData);
		String text2 = Hex.toHexString(decrData);

		System.out.println("Input: " + text0 + "\n" + "Encr:  " + text1 + "\n" + "Decr: " + text2);

		if (text0.equals(text2)) {
			System.out.println("Success");
		} else {
			System.out.println("Fail");
		}

	}

}
