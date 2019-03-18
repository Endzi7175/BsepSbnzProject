package rs.ac.uns.ftn.crypto;

import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Scanner;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import rs.ac.uns.ftn.crypto.cerificates.CertificateGenerator;
import rs.ac.uns.ftn.crypto.cerificates.CertificateUtils;
import rs.ac.uns.ftn.crypto.data.IssuerData;
import rs.ac.uns.ftn.crypto.data.SubjectData;
import rs.ac.uns.ftn.crypto.keystore.KeyStoreMenager;

public class App {

	public static void main(String[] args){
		Security.addProvider(new BouncyCastleProvider());
		Scanner sc = new Scanner(System.in);
		System.out.println("===== Konzolna aplikacija za upravljanje sertifikatima i kljucevima =====");
		Scanner keyboard = new Scanner(System.in);
		int choice = 0;
		do {
			menu();
			choice = keyboard.nextInt();
			switch(choice) {
			case 1: {
				addNewCertificate(sc);
				break;
			}
			case 2: {
				//showKeyStoreContent();
				break;
			}
			case 3: {
				//createNewSelfSignedCertificate();
				break;
			}
			case 4: {
				//createNewIssuedCertificate();
				break;
			}
			}
		} while(choice != 5);
		keyboard.close();
		
	
		
	}
	public static void addNewCertificate(Scanner sc){
		KeyStoreMenager ksMenager = new KeyStoreMenager();
		//ksMenager.createKeyStore("certificates","123");
		ksMenager.loadKeySotre("certificates", "123");
		try {
			ksMenager.generateCertificates();
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
		
		CertificateGenerator cg = new CertificateGenerator();

		SubjectData sd = CertificateUtils.enterSubjectData(sc);
		IssuerData id = CertificateUtils.choseCertIssuer(sc);
		
		RDN cn = sd.getX500name().getRDNs(BCStyle.CN)[0];
		String cnSubject = IETFUtils.valueToString(cn.getFirst().getValue());
		
		cn = id.getX500name().getRDNs(BCStyle.CN)[0];
		String cnIssuer = IETFUtils.valueToString(cn.getFirst().getValue());
		
		//pre dodavanja sertifikata prvo se proverava validnost svih sertifikata u lancu sertifikata
		Certificate[] certChainIssuer = ksMenager.getCertificateChain(cnIssuer);
		System.out.println("Proverava se validnost sertifikata izdavaoca... ");
		if (CertificateUtils.verifyCertChain(certChainIssuer)){
			//generisi nov sertifikat
			Certificate cert = cg.generateCertificate(sd, id);
			//generisi nov lanac sertifikata u odnosu na lanac sertifikata issuera
			Certificate[] certChainSubject = new Certificate[certChainIssuer.length + 1];
			System.arraycopy(certChainIssuer, 0, certChainSubject, 1, certChainIssuer.length);
			certChainSubject[0] = cert;
			ksMenager.addCertificate(cnSubject, sd.getPrivateKey(),  cnSubject.toCharArray(), certChainSubject, "certificates", "123");
			System.out.println("Sertifikat uspesno dodat.");
		}else{
			System.out.println("neuspesno dodavanje sertifikata.");
		}
	}
	private static void menu() {
		System.out.println("==================================");
		System.out.println("1.	Dodaj nov sertifikat");
		System.out.println("2.	Show key store content");
		System.out.println("3.	Create new self signed certificate");
		System.out.println("4.	Create new issued certificate");
		System.out.println("5.	Exit");
		System.out.print(">>>");
	}
}
