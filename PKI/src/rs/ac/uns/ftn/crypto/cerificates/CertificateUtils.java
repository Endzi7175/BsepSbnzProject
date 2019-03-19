package rs.ac.uns.ftn.crypto.cerificates;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import rs.ac.uns.ftn.crypto.data.IssuerData;
import rs.ac.uns.ftn.crypto.data.SubjectData;
import rs.ac.uns.ftn.crypto.keystore.KeyStoreMenager;

public class CertificateUtils {
	public static SubjectData enterSubjectData(Scanner sc) {
		try {
			KeyPair keyPairSubject = generateKeyPair();
			String subjectName = "";
			String organization = "";
			String organizationUnit ="";
			String countryCode = "";
			String startDateStr = "";
			String endDateStr = "";
			
			System.out.print("Enter the software name that the certificate is issued to: ");
			subjectName = sc.nextLine();
			System.out.print("Enter organization name: ");
			organization = sc.nextLine();
			System.out.print("Enter organization unit name: ");
			organizationUnit = sc.nextLine();
			System.out.print("Enter country code: ");
			countryCode = sc.nextLine();
			System.out.print("Certificate valid from: [format : yyyy-MM-dd] ");
			startDateStr = sc.nextLine();
			System.out.print("Certificate valid to: [format : yyyy-MM-dd] ");
			endDateStr = sc.nextLine();

			SimpleDateFormat iso8601Formater = new SimpleDateFormat("yyyy-MM-dd");
			Date startDate = iso8601Formater.parse(startDateStr);
			Date endDate = iso8601Formater.parse(endDateStr);
			
			//Serijski broj sertifikata
			String sn= (KeyStoreMenager.numberOfCertificates() + 1) + "";
			//klasa X500NameBuilder pravi X500Name objekat koji predstavlja podatke o vlasniku
			X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
		    builder.addRDN(BCStyle.CN, subjectName);
		    builder.addRDN(BCStyle.O, organization);
		    builder.addRDN(BCStyle.OU, organizationUnit);
		    builder.addRDN(BCStyle.C, countryCode);
		    return new SubjectData(keyPairSubject.getPublic(), keyPairSubject.getPrivate(), builder.build(), sn, startDate, endDate);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return null;
	}
	public static KeyPair generateKeyPair() {
        try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); 
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(2048, random);
			return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
        return null;
	}
	public static IssuerData choseCertIssuer(Scanner sc){
		KeyStoreMenager ksMenager = new KeyStoreMenager();
		ksMenager.loadKeySotre("certificates","123");
		Enumeration<String> aliasesNum = null;
		
		aliasesNum = ksMenager.aliases();
		
		Map<Integer, X509Certificate > map = new HashMap<Integer, X509Certificate>();
		int num = 1;
		while(aliasesNum.hasMoreElements()){	
			String alias = aliasesNum.nextElement();
			X509Certificate cert =	ksMenager.readCertificate("certificates", "123", alias);
			System.out.println(num + ".    Subject name: " + cert.getSubjectX500Principal().getName());
			//System.out.println("      Issuer name: " + cert.getIssuerX500Principal().getName());
			map.put(num, cert);
			num++;
		}
		int opt = 0;
		do{
			System.out.print("Choose certificate issuer: ");
			opt = sc.nextInt();

		}while(opt < 0 || opt > num);
		X509Certificate issuer = map.get(opt);

		//preko imena izdavaoca pronalazimo private key
		X500Name x500name = null;
		try {
			x500name = new JcaX509CertificateHolder(issuer).getSubject();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		RDN cn = x500name.getRDNs(BCStyle.CN)[0];
		String commonName = IETFUtils.valueToString(cn.getFirst().getValue());
		
		PrivateKey issuerPK = ksMenager.getKey(commonName, commonName, "certificates", "123");
		return new IssuerData(issuerPK, x500name);
		
	}
	public static X509Certificate ChoseCert(Scanner sc){
		KeyStoreMenager ksMenager = new KeyStoreMenager();
		ksMenager.loadKeySotre("certificates","123");
		Enumeration<String> aliasesNum = null;
		
		aliasesNum = ksMenager.aliases();
		
		Map<Integer, X509Certificate > map = new HashMap<Integer, X509Certificate>();
		int num = 1;
		while(aliasesNum.hasMoreElements()){	
			String alias = aliasesNum.nextElement();
			X509Certificate cert =	ksMenager.readCertificate("certificates", "123", alias);
			System.out.println(num + ".    Subject name: " + cert.getSubjectX500Principal().getName());
			System.out.println("      Issuer name: " + cert.getIssuerX500Principal().getName());
			map.put(num, cert);
			num++;
		}
		int opt = 0;
		do{
			System.out.print("Choose the certificate to revoke: ");
			opt = sc.nextInt();
		}
		while(opt < 0 || opt > num);
		return map.get(opt);
	}
	public static boolean verifyCertChain(Certificate[] certChain){
		KeyStoreMenager ksMenager = new KeyStoreMenager();
		if (certChain.length == 1){
			try {
				if (ksMenager.isRevoked((X509Certificate)certChain[0])){
					System.out.println("Chosen issuer certificate has been revoked.");
					return false;
				}
				certChain[0].verify(certChain[0].getPublicKey());
				return true;
			} catch (InvalidKeyException e) {
				return false;
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
			} catch (SignatureException e) {
				e.printStackTrace();
			}
			return false;
		}
		for (int i = 0; i < certChain.length -1; i++){
			Certificate subject = certChain[i];
			//proverava da li je sertifikat povucen
			if (ksMenager.isRevoked((X509Certificate)subject)){
				System.out.println("Chosen issuer certificate has been revoked.");
				return false;
			}
			Certificate issuer = certChain[i + 1];
			try {
				subject.verify(issuer.getPublicKey());
			} catch (InvalidKeyException e) {
				return false;
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
			} catch (SignatureException e) {
				e.printStackTrace();
			}
		}
		//na kraju root proverava samog sebe
		try {
			if (ksMenager.isRevoked((X509Certificate)certChain[certChain.length-1])){
				System.out.println("Chosen issuer certificate has been revoked.");
				return false;
			}
			certChain[certChain.length-1].verify(certChain[certChain.length-1].getPublicKey());
		} catch (InvalidKeyException e) {
			return false;
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return true;
	}
	
}
