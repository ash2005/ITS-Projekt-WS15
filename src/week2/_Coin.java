package week2;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SRAEngine;

public class _Coin {

	private byte[] c1, c2;
	
	public _Coin() {
		
	}
	
	public String prepareCoin() {
		String m1, m2;
		
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[20];
	    random.nextBytes(bytes);
	    
	    int test = (bytes[15] & 0xFF) >> 7;
	    
	    int randomMsg = random.nextInt();
	    if (test == 0) {
	    	
	    	m1 = "Head" + randomMsg;
	    	m2 = "Tail" + randomMsg;
	    }
	    else {
	    	m1 = "Tail" + randomMsg;
	    	m2 = "Head" + randomMsg;
	    }
	    
	    this.c1 = m1.getBytes();
	    this.c2 = m2.getBytes();
	    
	    return "" + randomMsg + "";
	}
	
	public void encrypt(AsymmetricCipherKeyPair keypair) {
		AsymmetricBlockCipher engEn = new SRAEngine();
		engEn.init(true, keypair.getPublic());
		
		try {
			this.c1 = engEn.processBlock(c1, 0, c1.length);
			this.c2 = engEn.processBlock(c2, 0, c2.length);
		} catch (InvalidCipherTextException error) {
			error.printStackTrace();
		}
	}
	
	public void decrypt(AsymmetricCipherKeyPair keypair) {
		AsymmetricBlockCipher engDe = new SRAEngine();
		engDe.init(false, keypair.getPrivate());
		
		try {

			this.c1 = engDe.processBlock(c1, 0, c1.length);
			this.c2 = engDe.processBlock(c2, 0, c2.length);
		} catch (InvalidCipherTextException error) {
			error.printStackTrace();
		}
	}
	
	public void printC () {
		try {
			System.out.println(new String(c1, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
//	public Boolean isFirstHead() {
//		return m1.substring(0, 4).equals("Head");
//	}
}
