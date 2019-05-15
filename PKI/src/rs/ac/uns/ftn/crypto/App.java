package rs.ac.uns.ftn.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Scanner;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import rs.ac.uns.ftn.crypto.cerificates.CertificateGenerator;
import rs.ac.uns.ftn.crypto.cerificates.CertificateUtils;
import rs.ac.uns.ftn.crypto.data.IssuerData;
import rs.ac.uns.ftn.crypto.data.SubjectData;
import rs.ac.uns.ftn.crypto.keystore.KeyStoreMenager;

public class App {
	
	private static final String REVOKE_FILE = "revokedCertificates";
	private static final String REVOKE_FILE_PASS = "123";
	private KeyStoreMenager ksMenager;
	public App(){
		ksMenager = new KeyStoreMenager();
	}
	
	public static void main(String[] args) throws CertificateEncodingException{
		
		Security.addProvider(new BouncyCastleProvider());
		Scanner sc = new Scanner(System.in);
		System.out.println("===== Console application for certificates management =====");
		Scanner keyboard = new Scanner(System.in);
		App PKI = new App();
		
		int choice = 0;
		do {
			menu();
			choice = keyboard.nextInt();
			keyboard.nextLine();
			switch(choice) {
			case 1: {
				PKI.addNewCertificate(sc);
				break;
			}
			case 2: {

				PKI.revokeCertificate(sc);
				break;
			}
			case 3: {
				PKI.showKeyStoreContent("certificates", "123");
				break;
			}
			case 4: {
				PKI.showKeyStoreContent("revokedCertificates", "123");
				break;
			}
			}
		} while(choice != 5);
		keyboard.close();
		
	
		
	}
	public void addNewCertificate(Scanner sc){
		//ksMenager.createKeyStore("revokedCertificates","123");
		ksMenager.createKeyStore("root", "123");
		ksMenager.loadKeySotre("root", "123");
		
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
		System.out.println("Checking issuer certificate in process... ");
		if (CertificateUtils.verifyCertChain(certChainIssuer)){
			//generisi nov sertifikat
			Certificate cert = cg.generateCertificate(sd, id);
			//generisi nov lanac sertifikata u odnosu na lanac sertifikata issuera
			Certificate[] certChainSubject = new Certificate[certChainIssuer.length + 1];
			System.arraycopy(certChainIssuer, 0, certChainSubject, 1, certChainIssuer.length);
			certChainSubject[0] = cert;
			ksMenager.addCertificate(cnSubject, sd.getPrivateKey(),  cnSubject.toCharArray(), certChainSubject, "client", "client");
			System.out.println("Certificate successfuly added.");
		}else{
			System.out.println("Certificate not added successfully.");
		}
	}
	public void showKeyStoreContent(String fileName, String password){
		KeyStoreMenager ksMenager = new KeyStoreMenager();
		ksMenager.loadKeySotre(fileName, password);
		//ksMenager.loadKeySotre("certificates", "123");

		Enumeration<String> aliasesNum = null;
		
		aliasesNum = ksMenager.aliases();
		System.out.println("========================================");
		while(aliasesNum.hasMoreElements()){
			String alias = aliasesNum.nextElement();
			X509Certificate cert =	ksMenager.readCertificate("certificates", "123", alias);
			System.out.println("      Subject name: " + cert.getSubjectX500Principal().getName());
			System.out.println("      Issuer name: " + cert.getIssuerX500Principal().getName());
			System.out.println("========================================");

		}
	}
	public void revokeCertificate(Scanner sc) throws CertificateEncodingException{
		ksMenager.loadKeySotre("certificates", "123");
		X509Certificate certToRevoke = CertificateUtils.ChoseCert(sc);
		
		System.out.print("Choose the cause of certificate revocation: ");
		revocationReasons();
		int opt = 0;
		do{
			opt = sc.nextInt();
		}
		while(opt < 1 || opt > 5);
		
		//TODO: write revocing certificate serial num and reason to file
		
		Enumeration<String> aliasesNum = ksMenager.aliases();
		ArrayList<X509Certificate> certsToRevoke = new ArrayList<>();
		while(aliasesNum.hasMoreElements()){
			String alias = aliasesNum.nextElement();
			Certificate[] certChain = ksMenager.getCertificateChain(alias);
			for (Certificate c : certChain){
				
				if (((X509Certificate)c).getSerialNumber().equals(certToRevoke.getSerialNumber())){
					certsToRevoke.add(ksMenager.readCertificate("certificates", "123", alias));
				}
			}
		}

		for (X509Certificate cert : certsToRevoke){
			X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
			RDN cn = x500name.getRDNs(BCStyle.CN)[0];
			
			String commonName = IETFUtils.valueToString(cn.getFirst().getValue());
			
			PrivateKey subjectPK = ksMenager.getKey(commonName, commonName, "certificates", "123");
			ksMenager.addCertificate(commonName, subjectPK,  commonName.toCharArray(), new Certificate[]{cert}, "revokedCertificates", "123");

		}
		
		
	}
	private static void menu() {
		System.out.println("========================================");
		System.out.println("1.	Issue new certificate");
		System.out.println("2.	Revoke certificate");
		System.out.println("3.	Show all certificates");
		System.out.println("4.	Show all revoked certificates");
		System.out.println("5.	Exit");
		System.out.print(">>>");
	}
	private static void revocationReasons() {
		System.out.println("========================================");
		System.out.println("1.	Certificate is no longer used");
		System.out.println("2.	Details of certificate are changed");
		System.out.println("3.	The certificate owner's private key was compromised or lost");
		System.out.println("4.	Certificates were stolen from CA");
		System.out.println("5.	Other");
		System.out.print(">>>");
	}
}
