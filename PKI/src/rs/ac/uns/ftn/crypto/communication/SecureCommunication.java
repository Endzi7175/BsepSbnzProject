/*package rs.ac.uns.ftn.crypto.communication;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

//import com.sun.java.util.jar.pack.Package.File;


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
		try {
			symmCipher = Cipher.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			asymmCipher = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
				
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
	
	private byte[] encrypt(File originalKeyFile, File encryptedKeyFile, File originalFile, File encryptedFile) {
		//TODO: Sifrovati otvoren tekst uz pomoc kombinacije simetricne i asimetricne sifre koju diktira najbolja praksa
		new EncryptData(originalFile, encryptedFile, 
                secretSymmetricKey);

		//obtain the ecrypted and pass it to rsa down
		new EncryptKey(publicKey, 
                originalKeyFile, encryptedKeyFile);
		//whole message bind together and prepare for sending
		return null;
	}
	
	private byte[] decrypt(File encryptedKeyReceived, File decreptedKeyFile, File encryptedFileReceived, File decryptedFile) {
		//TODO: Desifrovati sifrat uz pomoc kombinacije simetricne i asimetricne sifre koju diktira najbolja praksa
		DecryptKey dk = new DecryptKey(privateKey,
                encryptedKeyReceived, decreptedKeyFile);

		new DecryptData(encryptedFileReceived, decryptedFile, 
                dk.getSecretKey);

		return null;//return decrypted dataaaaa
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
*/