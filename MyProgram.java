

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MyProgram {
	private static final String IV_DEFAULT_AES = "g8v20drvOmIx2PuR"; // 16 bytes forAES
	private static final String IV_DEFAULT_Twofish = "8v2sa2d30Ix2P9mA"; // 16 bytes for Two fish
	
	public static void main (String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		
		// check if bouncy Castle is successfully set up 
        if (Security.getProvider("BC") == null){
            System.out.println("Bouncy Castle provider is NOT available");
        }
        else{
            System.out.println("Bouncy Castle provider is available");
        }
        System.out.print(" ");
        
        Scanner scanner = new Scanner(System.in);
        System.out.println("Please enter the plantext: ");
        byte[] message = scanner.nextLine().getBytes();
        
        // AES
        String ivAES = IV_DEFAULT_AES;
        final IvParameterSpec ivParameterSpec = new IvParameterSpec(getUTF8Bytes(ivAES)); // get IV for CFB
        
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding","BC"); // choose CFB because its the best choice for encrypting streams of characters at a text terminal
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        System.out.println(" ");
        System.out.println("------AES------");
        
        byte[] cipherText = encryptByAES(message, cipher, key, ivParameterSpec);
        System.out.println("the cipher text by AES is:"+ Arrays.toString(cipherText));
        
        String plainText = decryptByAES(message.length, cipher, cipherText, key, ivParameterSpec);
        System.out.println("the decipher by AES message is: " + plainText);
        
        // ---------------------------------------------------------------------
        
        // TwoFish
        String ivTwofish = IV_DEFAULT_Twofish;
        final IvParameterSpec ivParameterSpecTwofish = new IvParameterSpec(getUTF8Bytes(ivTwofish)); // get IV for TwoFish 
        
        cipher = Cipher.getInstance("Twofish/CFB/PKCS5Padding","BC");
        keyGen = KeyGenerator.getInstance("Twofish");
        keyGen.init(256);
        key = keyGen.generateKey();
        System.out.println(" ");
        System.out.println("------Twofish-----");
        
        
        cipherText = encryptByTwofish(message, cipher, key, ivParameterSpecTwofish);
        System.out.println("the cipher text by Twofish is: "+ Arrays.toString(cipherText));
        
        plainText = decryptByTwofish(message.length, cipher, cipherText, key, ivParameterSpecTwofish);
        System.out.println("the decipher text by Twofish is: "+ plainText);
        // ---------------------------------------------------------------------
        
        // RSA 
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC"); // ECB block mode
        keyPairGen.initialize(1024); 
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        PrivateKey priKey = keyPair.getPrivate();
        System.out.println(" ");
        System.out.println("------RSA------");
        
        cipherText = encryptByRSA(message, pubKey, cipher);
        System.out.println("the cipher text by RSA is: "+ Arrays.toString(cipherText));
        
        plainText = decryptByRSA(message.length, priKey, cipherText, cipher);
        System.out.println("the cipher text by RSA is: "+ plainText);
        
        // RSA signature
        Signature signature = Signature.getInstance("SHA1withRSA","BC");
        signature.initSign(priKey);
        signature.update(message);
        
        byte[] sigBytes = signature.sign();
        signature.initVerify(pubKey);
        signature.update(message);
        
        if (signature.verify(sigBytes)) {
        	System.out.println("Signature verification succeeded.\n ");
        } else {
        	System.out.println("Signature verification failed.\n");
        }
        // ---------------------------------------------------------------------
        
        // extra credits
        System.out.println(" ");
        System.out.println("-----Extra Credit-----");
        String[] strs = getRandomStringArray(); // get 100 random strings
        
        // 100 time AES 
        long start1 = System.currentTimeMillis();
        cipher = Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
        for (int i = 0; i < strs.length; i++) {
        	keyGen = KeyGenerator.getInstance("AES");
        	keyGen.init(256);
        	key = keyGen.generateKey();
        	encryptByAES(strs[i].getBytes(), cipher, key, ivParameterSpec);
        }
		long end1 = System.currentTimeMillis();
		long time1 = end1 - start1;
		System.out.println("100 times AES Encryption costs " + time1+ "ms");
		// ---------------------------------------------------------------------
		
		// 100 times TwoFish 
		long start2 = System.currentTimeMillis();
	    cipher = Cipher.getInstance("Twofish/CFB/PKCS5Padding","BC");
	    for (int i = 0; i < strs.length; i++) {
	    	keyGen = KeyGenerator.getInstance("Twofish");
	    	keyGen.init(256);
	    	key = keyGen.generateKey();
	    	encryptByTwofish(strs[i].getBytes(), cipher, key, ivParameterSpec);
	    	}
	    long end2 = System.currentTimeMillis();
	    long time2 = end2 - start2;
	    System.out.println("100 times Twofish Encryption costs " + time2+ "ms");
		// ---------------------------------------------------------------------
		
		// 100 times RSA
	    long start3 = System.currentTimeMillis();
	    cipher = cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
	    for (int i = 0; i < strs.length; i++) {
	    	KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
	    	kpGen.initialize(1024);
	    	keyPair = kpGen.generateKeyPair();
	    	pubKey = keyPair.getPublic();
	    	encryptByRSA(strs[i].getBytes(), pubKey, cipher);
	    	}
	    long end3 = System.currentTimeMillis();
	    long time3 = end3 - start3;
	    System.out.println("100 times RSA Encryption costs " + time3 + "ms");
	    // ---------------------------------------------------------------------
	    
	    System.out.println(" ");
	    // time comparison
	    System.out.println("AES encryption is " +(time3 - time1) +"ms than RSA encryption");
	    System.out.println("Twofish encryption is " +(time3 - time2) +"ms than RSA encryption");
	    System.out.println("AES encryption is " +(time2 - time1) +"ms than Twofish encryption");
	    // ---------------------------------------------------------------------
	    
	}

	
	private static String[] getRandomStringArray() {
		String[] strArray = new String[100];
		StringBuilder sb = new StringBuilder();
		String allChar = "abcdefghijklmnopqrstuvwxyz"
				+ "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				+ "0123456789";
		
		for(int i = 0; i < 100; i++) {
			int len = RandomNum(0,100); // random string length
			for (int j = 0; j< len; j++) {
				int inx =(int) (allChar.length() * Math.random());
				sb.append(allChar.charAt(inx));
			}
			strArray[i] = sb.toString();
			sb.setLength(0); // reset stringBuilder
		}
		return strArray;
	}
	
	private static int RandomNum (int min, int max) {
		int i;
		i = (int) (Math.random() *(max - min + 1) + min);
		//math.random() is [0,1);
		return i;
	}

	private static String decryptByRSA(int length, PrivateKey priKey, byte[] cipherText, Cipher cipher) {
		try {
			byte[] plainTextBytes = new byte[length];
			cipher.init(Cipher.DECRYPT_MODE, priKey);
			plainTextBytes = cipher.doFinal(cipherText);
			return new String(plainTextBytes);
		}catch (Exception e) {
			System.out.println("decryption by RSA fails");
		}
		return null;
	}

	private static byte[] encryptByRSA(byte[] message, PublicKey pubKey, Cipher cipher) {
		try {
			byte[] cipherText = new byte[message.length];
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			cipherText = cipher.doFinal(message);
			return cipherText;
		} catch(Exception e) {
			System.out.println("encryption by RSA fails");
		}
		return null;
	}

	private static String decryptByTwofish(int length, Cipher cipher, byte[] cipherText, SecretKey key, IvParameterSpec ivParameterSpec) {
		try {
			byte[] plainTextBytes = new byte[length];
			cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
			plainTextBytes = cipher.doFinal(cipherText);
			return new String(plainTextBytes);
		}
		catch (Exception e) {
			System.out.println("decryption by Twofish fails");
		}
		return null;
	}

	private static byte[] encryptByTwofish(byte[] message, Cipher cipher, SecretKey key, IvParameterSpec ivParameterSpec) throws Exception {
		byte[] cipherText = new byte[message.length];
		cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
		cipherText = cipher.doFinal(message);
		return cipherText;

	}

	private static byte[] getUTF8Bytes(String input) {
		return input.getBytes(StandardCharsets.UTF_8);
	}

	private static String decryptByAES(int length, Cipher cipher, byte[] cipherText, SecretKey key, IvParameterSpec ivParameterSpec) throws Exception {
		byte[] plainTextBytes = new byte[length];
		cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
		plainTextBytes = cipher.doFinal(cipherText);
		return new String(plainTextBytes);
	}

	
	private static byte[] encryptByAES(byte[] message, Cipher cipher, SecretKey key,IvParameterSpec ivParameterSpec ) throws Exception {

		byte[] cipherOutput = new byte[message.length];
		cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
		cipherOutput = cipher.doFinal(message);
		return cipherOutput;
		
	}

}
