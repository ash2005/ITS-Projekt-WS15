package week2;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.crypto.generators.SRAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;

public class CoinFlip {
	private AsymmetricCipherKeyPair keypair;
	private String step0_randomString;
	private String step0_m1;
	private String step0_m2;
	private byte[] step0_c1;
	private byte[] step0_c2;
	
	private byte[] step1_c1;
	
	private byte[] step2_c1;
	
	private String step3_randomString;
	
	private AsymmetricCipherKeyPair step4_foreignkeypair;
	
	public static void main(String[] args) {
		SRAKeyPairGenerator keygen = new SRAKeyPairGenerator();
		keygen.init(
					new SRAKeyGenerationParameters(null,null, new SecureRandom(), 1024, 80)
				);

		AsymmetricCipherKeyPair keypair = keygen.generateKeyPair();
		BigInteger p = ((RSAPrivateCrtKeyParameters)keypair.getPrivate()).getP();
		BigInteger q = ((RSAPrivateCrtKeyParameters)keypair.getPrivate()).getQ();
		
		CoinFlip alice = new CoinFlip(p,q);
		CoinFlip bob = new CoinFlip(p,q);
		
		
		// Step0: A -> B : {M1 ++ N}KA, {M2 ++ N}KA,
		bob.step0_getCoins(alice.step0_sendCoins());
		
		// Step1: B -> A : {{M1 ++ N}KA}KB
		alice.step1_getChoice(bob.step1_sendChoice());
		
		// Step2: A -> B : {M1 ++ N}KB
		bob.step2_getChoice(alice.step2_sendChoice());
		
		// Step3: B -> A : N
		alice.step3_getRandomString(bob.step3_sendRandomString());
		
		// Step4: A -> B : KA
		//        B -> A : KB
		bob.step4_getKey(alice.step4_sendKey());
		alice.step4_getKey(bob.step4_sendKey());
		
		//verify
		alice.verifyStep1();
		bob.verifyStep0();
	}

	
	private void verifyStep1() {
		String x = new String(decryptOwnKey(decryptForeignKey(this.step1_c1)));
		
		System.out.println("Alice: Bob has choosen " 
		      + x.substring(0, 4) + " (" + this.step0_m1.substring(0, 4) + ") " 
				+ x.substring(0, 4).equals(this.step0_m1.substring(0, 4)));
		System.out.println("Alice: Nonce is "
		      + x.substring(4) + " (" + this.step0_randomString + ") "  
				+ x.substring(4).equals(this.step0_randomString));
	}


	private void verifyStep0() {
		String x = new String((decryptForeignKey(this.step0_c1)));
		
		System.out.println(x);
		
	}


	private byte[][] step0_sendCoins() {
		this.step0_randomString = randomString(10);
		
	    if (new SecureRandom().nextBoolean()) {
	    	this.step0_m1 = "HEAD";
	    	this.step0_m2 = "TAIL";
	    }
	    else {
	    	this.step0_m2 = "HEAD";
	    	this.step0_m1 = "TAIL";
	    }
	    
	    this.step0_m1 += step0_randomString;
	    this.step0_m2 += step0_randomString;
	    
	    this.step0_c1 = encryptOwnKey(this.step0_m1.getBytes());
	    this.step0_c2 = encryptOwnKey(this.step0_m2.getBytes());
	    
	    byte[][] ret = {this.step0_c1, this.step0_c2}; 
	    
	    return ret;
	}
	
	private void step0_getCoins (byte[][] coin) {
		this.step0_c1 = coin[0];
		this.step0_c2 = coin[1];
	}
	
	private byte[] step1_sendChoice(){
		this.step1_c1 = encryptOwnKey(this.step0_c1);
		
		return this.step1_c1;
	}
	
	private void step1_getChoice(byte[] choice) {
		this.step1_c1 = choice;
	}
	
	private byte[] step2_sendChoice(){
		this.step2_c1 = decryptOwnKey(this.step1_c1);
		
		return this.step2_c1;
	}
	
	private void step2_getChoice(byte[] choice) {
		this.step2_c1 = choice;
	}
	
	private String step3_sendRandomString() {
		this.step3_randomString = new String(decryptOwnKey(this.step2_c1)).substring(4);
		
		return this.step3_randomString;
	}
	
	private void step3_getRandomString(String randomString) {
		this.step3_randomString = randomString;
	}
	
	private AsymmetricCipherKeyPair step4_sendKey() {
		return keypair;
	}
	private void step4_getKey(AsymmetricCipherKeyPair key) {
		this.step4_foreignkeypair = key;
	}
	
	public byte[] encryptOwnKey(byte[] text) {
		return encrypt(text, this.keypair);
	}
	
	public byte[] encryptForeignKey(byte[] text) {
		return encrypt(text, this.step4_foreignkeypair);
	}
	
	public byte[] encrypt(byte[] text, AsymmetricCipherKeyPair keypair) {
		AsymmetricBlockCipher engEn = new SRAEngine();
		engEn.init(true, keypair.getPublic());

		try {
			text = engEn.processBlock(text, 0, text.length);
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return text;
	}
	
	public byte[] decryptOwnKey(byte[] text) {
		return decrypt(text, this.keypair);
	}
	
	public byte[] decryptForeignKey(byte[] text) {
		return decrypt(text, this.step4_foreignkeypair);
	}
	
	public byte[] decrypt(byte[] text, AsymmetricCipherKeyPair keypair) {
		AsymmetricBlockCipher engEn = new SRAEngine();
		engEn.init(false, keypair.getPrivate());

		try {
			text = engEn.processBlock(text, 0, text.length);
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return text;
	}


	public CoinFlip(BigInteger p, BigInteger q) {
		SRAKeyPairGenerator keygen = new SRAKeyPairGenerator();
		keygen.init(
					new SRAKeyGenerationParameters(p,q, new SecureRandom(), 1024, 80)
				);

		this.keypair = keygen.generateKeyPair();
	}

	String randomString( int len ){
		final String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"+"ABCDEFGHIJKLMNOPQRSTUVWXYZ".toLowerCase();
		SecureRandom rnd = new SecureRandom();
		StringBuilder sb = new StringBuilder(len);
		for (int i = 0; i < len; i++)
			sb.append(AB.charAt(rnd.nextInt(AB.length())));
		return sb.toString();
	}
}

