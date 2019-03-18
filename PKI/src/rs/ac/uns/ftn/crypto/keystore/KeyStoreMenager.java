package rs.ac.uns.ftn.crypto.keystore;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import rs.ac.uns.ftn.crypto.cerificates.CertificateGenerator;
import rs.ac.uns.ftn.crypto.cerificates.CertificateUtils;
import rs.ac.uns.ftn.crypto.data.IssuerData;
import rs.ac.uns.ftn.crypto.data.SubjectData;


public class KeyStoreMenager {
	private KeyStore keyStore;
	
	public KeyStoreMenager(){
		try {
			keyStore = KeyStore.getInstance("JKS", "SUN");
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
	}
	public void createKeyStore(String fileName, String password){
		try {
			keyStore.load(null, password.toCharArray());
			keyStore.store(new FileOutputStream("files/" + fileName + ".jks"), password.toCharArray());
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	public void loadKeySotre(String keyStoreName, String keyStorePass){
		try {
				keyStore.load(new FileInputStream("files/" + keyStoreName + ".jks"), keyStorePass.toCharArray());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	public void addCertificate(String alias, PrivateKey privateKey, char[] password, Certificate[] certChain, String keyStoreName, String keyStorePass){
		try {
			//dodaj sertifikat
			keyStore.setKeyEntry(alias, privateKey, password, certChain);
			//upisi u fajl
			keyStore.store(new FileOutputStream("files/" + keyStoreName + ".jks"), keyStorePass.toCharArray());
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	public Certificate[] getCertificateChain(String alias){
		try {
			return keyStore.getCertificateChain(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}
	public X509Certificate readCertificate(String keyStoreFile, String keyStorePass, String alias) {
		
		try {
			keyStore.load(new FileInputStream("files/" + keyStoreFile + ".jks"), keyStorePass.toCharArray());
			if(keyStore.isKeyEntry(alias)){
				X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
				return cert;
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public void generateCertificates() throws ParseException{
		KeyPair keyPairSubject = CertificateUtils.generateKeyPair();
		
		//Datumi od kad do kad vazi sertifikat
		SimpleDateFormat iso8601Formater = new SimpleDateFormat("yyyy-MM-dd");
		Date startDate = iso8601Formater.parse("2017-12-31");
		Date endDate = iso8601Formater.parse("2022-12-31");
		
		//Serijski broj sertifikata
		String sn="1";
		//klasa X500NameBuilder pravi X500Name objekat koji predstavlja podatke o vlasniku
		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
	    builder.addRDN(BCStyle.CN, "MegaTravelRoot");

	    builder.addRDN(BCStyle.O, "Travel Agency");
	    builder.addRDN(BCStyle.OU, "root");
	    builder.addRDN(BCStyle.C, "RS");

	    SubjectData sd =  new SubjectData(keyPairSubject.getPublic(), keyPairSubject.getPrivate(), builder.build(), sn, startDate, endDate);
	    IssuerData id = new IssuerData(keyPairSubject.getPrivate(), builder.build());
	    CertificateGenerator cg = new CertificateGenerator();
	    
	    Certificate cert = cg.generateCertificate(sd, id);
	    addCertificate("MegaTravelRoot", keyPairSubject.getPrivate(), new String("MegaTravelRoot").toCharArray(), new Certificate[]{cert}, "certificates", "123");
	    
	}
	public Enumeration<String> aliases(){
		try {
			return this.keyStore.aliases();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}
	public PrivateKey getKey(String alias, String password){
		try {
			return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	public static int numberOfCertificates(){
		KeyStoreMenager ksMenager = new KeyStoreMenager();
		ksMenager.loadKeySotre("certificates","123");
		int numOfCerts = 0;
		Enumeration<String> certs = null;
		try {
			certs = ksMenager.keyStore.aliases();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		while(certs.hasMoreElements()){
			numOfCerts++;
			certs.nextElement();
		}
		return numOfCerts;
	}
	

	public static void main(String[] args) throws ParseException{
		
		

	}
}
