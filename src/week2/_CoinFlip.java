package week2;

public class _CoinFlip {

	public static void main(String[] args) {
		
		_Coin coin = new _Coin();
		
		// Players
		_Person alice = new _Person(null, null);
		_Person bob = new _Person(alice.getP(),alice.getQ());
		
		//Alice generates two message, M1 = “Heads” and M1 = “Tails”. She adds a random string to both messages.
		alice.prepareCoin(coin);
		
		// Alice sends EA(M1) and EA(M2) to Bob in random order, i.e. Bob does not know which is which.
		coin.encrypt(alice.getKeypair());
		
		// Bob picks one of the messages. We call this message EA(M).
		// Bob chooses the first
		// Bob generates key B and sends EB(EA(M)) to Alice.
		coin.encrypt(bob.getKeypair());
		
		// Alice decrypts the message with her key and sends DA(EB(EA(M))) = EB(M) to Bob.
		coin.decrypt(alice.getKeypair());
		
		// Bob computes DB(EB(M)) = M. This is the coin flip result. He	sends M to Alice.
		coin.decrypt(bob.getKeypair());
		
		// Bob chooses
		System.out.println("Bob has choosen the first: ");
		coin.printC();
		
		// Alice checks randomnumber
		System.out.println("Alive verifies randomMsg: ");
		System.out.println(alice.getRandomMsg());
		
	}

}
