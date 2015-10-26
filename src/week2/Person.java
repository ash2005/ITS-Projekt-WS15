package week2;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.SRAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;

public class Person {
	private AsymmetricCipherKeyPair keypair;
	private String randomMsg;
	
	public Person(BigInteger p, BigInteger q) {
		// Create Keys
		SRAKeyPairGenerator keygen = new SRAKeyPairGenerator();
		keygen.init(new SRAKeyGenerationParameters(
				p,q,
				new SecureRandom(), // prng
				1024, // strength
				80// certainty
		));

		this.keypair = keygen.generateKeyPair();
	}

	public AsymmetricCipherKeyPair getKeypair() {
		return keypair;
	}

	public void setKeypair(AsymmetricCipherKeyPair keypair) {
		this.keypair = keypair;
	}
	
	public void prepareCoin(Coin x) {
		this.randomMsg = x.prepareCoin();
	}

	public String getRandomMsg() {
		return randomMsg;
	}

	public void setRandomMsg(String randomMsg) {
		this.randomMsg = randomMsg;
	}
	
	public BigInteger getP() {
		return ((RSAPrivateCrtKeyParameters)keypair.getPrivate()).getP();
	}
	
	public BigInteger getQ() {
		return ((RSAPrivateCrtKeyParameters)keypair.getPrivate()).getQ();
	}
	
}
