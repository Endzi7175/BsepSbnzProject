package rs.ac.uns.ftn.crypto.communication;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class SecureCommunication {
	
	private SecretKey secretSymmetricKey;
	private KeyPair pairAsymmetric;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Cipher symmCipher;
    private Cipher asymmCipher;

	
	public SecureCommunication() {
		Security.addProvider(new BouncyCastleProvider());
		secretSymmetricKey = generateSecretKey();
		pairAsymmetric = generateKeyPair();
		privateKey = pairAsymmetric.getPrivate();
		publicKey = pairAsymmetric.getPublic();
		symmCipher = Cipher.getInstance("AES");
		asymmCipher = Cipher.getInstance("RSA");
				
	}
	

	private SecretKey generateSecretKey() {
		//Generisati i vratiti AES kljuc duzine koju diktira najbolja praksa
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256); // for example
		SecretKey secretKey = keyGen.generateKey();
		return secretKey;
	}
	
	private KeyPair generateKeyPair() {
		//Generisati i vratiti RSA kljuceve duzine koju diktira najbolja praksa
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(2048, random);
		KeyPair pair = keyGen.generateKeyPair();
		//PrivateKey priv = pair.getPrivate();
		//PublicKey pub = pair.getPublic();
		return pair;
	}
	
	private byte[] encrypt(String plainText, PublicKey publicKey) {
		//TODO: Sifrovati otvoren tekst uz pomoc kombinacije simetricne i asimetricne sifre koju diktira najbolja praksa
		return null;
	}
	
	private byte[] decrypt(byte[] cipherText, SecretKey key) {
		//TODO: Desifrovati sifrat uz pomoc kombinacije simetricne i asimetricne sifre koju diktira najbolja praksa
		
		
		return null;
	}
	
	private byte[] sign(byte[] data, PrivateKey privateKey) {
		//TODO: Izvrsiti digitalno potpisivanje prateci najbolje prakse
		return null;
	}
	
	private boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
		//TODO: Izvrsiti proveru digitalnog potpisa
		return false;
	}

}
