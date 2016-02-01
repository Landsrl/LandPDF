package it.land;


import it.land.responses.IsValidResponse;
import it.land.responses.SignedResponse;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import org.apache.axis2.context.MessageContext;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

/**
 * 
 * @author Riccardo Bracci & Marco Costa
 *
 */
public class PdfService
{

	private String certificate = null;
	
	private static Logger logger = Logger.getLogger(PdfService.class);
	
	private boolean isPades = false;
	
	private boolean isCades = false;

	public PdfService()
	{
		try
		{
			activateLog();
		} catch (IOException e)
		{
			System.out.println(e.getMessage());
		}
		
	}

	public IsValidResponse isValid(byte[] pdf)
	{
		IsValidResponse toReturn = new IsValidResponse();
		
		
		if(	(pdf == null) || (pdf.length == 0))
		{
			Error error = new Error();
			error.setCode(1009);
			error.setDescription("Nessun pdf ricevuto in input alla request. Si prega di verificare.");
			toReturn.setError(error);
			return toReturn;
		}
		
		Security.addProvider(new BouncyCastleProvider());
		
		certificate = this.getClass().getClassLoader()
				.getResource("GeoTrust_CA_for_Adobe.pem").getPath();
		
		KeyStore ks = null;
		try
		{
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e)
		{
			Error error = new Error();
			error.setCode(1001);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		try
		{
			ks.load(null, null);
		} catch (NoSuchAlgorithmException e)
		{
			Error error = new Error();
			error.setCode(1002);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (CertificateException e)
		{
			Error error = new Error();
			error.setCode(1003);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (IOException e)
		{
			Error error = new Error();
			error.setCode(1004);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		CertificateFactory cf = null;
		try
		{
			cf = CertificateFactory.getInstance("X509");
		} catch (CertificateException e)
		{
			Error error = new Error();
			error.setCode(1005);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		FileInputStream is1 = null;
		try
		{
			is1 = new FileInputStream(certificate);
		} catch (FileNotFoundException e)
		{
			Error error = new Error();
			error.setCode(1006);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		X509Certificate cert1 = null;
		try
		{
			cert1 = (X509Certificate) cf.generateCertificate(is1);
		} catch (CertificateException e)
		{
			Error error = new Error();
			error.setCode(1007);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		try
		{
			ks.setCertificateEntry("cacert", cert1);
		} catch (KeyStoreException e)
		{
			Error error = new Error();
			error.setCode(1008);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		PdfReader reader = null;
		try
		{
			reader = new PdfReader(pdf);
		} catch (IOException e)
		{
			Error error = new Error();
			error.setCode(1009);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		AcroFields af = reader.getAcroFields();
		ArrayList<String> names = af.getSignatureNames();
		for (String name : names)
		{
			PdfPKCS7 pk = af.verifySignature(name);
			X509Certificate cert = (X509Certificate) pk.getSigningCertificate();
			try
			{
				cert.checkValidity();
			} catch (CertificateExpiredException e)
			{
				Error error = new Error();
				error.setCode(0);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				toReturn.setIsSigned(true);
				toReturn.setIsValid(false);
				return toReturn;
			} catch (CertificateNotYetValidException e)
			{
				Error error = new Error();
				error.setCode(0);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				toReturn.setIsSigned(true);
				toReturn.setIsValid(false);
				return toReturn;
			}
		}
		if (names.size() <= 0)
		{
			Error error = new Error();
			error.setCode(0);
			error.setDescription("OK");
			toReturn.setError(error);
			toReturn.setIsSigned(false);
			toReturn.setIsValid(false);
			return toReturn;
		}
		Error error = new Error();
		error.setCode(0);
		error.setDescription("OK");
		toReturn.setError(error);
		toReturn.setIsSigned(true);
		toReturn.setIsValid(true);
		return toReturn;
	}

	
	/**
	 * Make a PAdES
	 * 
	 * @param certname Name of the P12 certificate
	 * @param pin Pin of the certificate
	 * @param pdf Pdf to sign
	 * @return The response composed by an Error object (that has a status and reason) and the PAdES 
	 */
	public SignedResponse signPdf(String certname, String pin, byte[] pdf)
	{
		isPades = true;
		return this.innerSign(certname, pin, pdf);
	}
	
	/**
	 * Make a CAdES
	 * 
	 * @param certname Name of the P12 certificate
	 * @param pin Pin of the certificate
	 * @param buffer Buffer to sign
	 * @return The response composed by an Error object (that has a status and reason) and the CAdES
	 */
	public SignedResponse signCades(String certname, String pin, byte[] buffer)
	{		
		isCades = true;
		return innerSign(certname, pin, buffer);
	}
	
	
	
	private SignedResponse innerSign(String certname, String pin, byte[] buffer)
	{
		long start = System.currentTimeMillis();
		
		logger.info("Inizio metodo di firma pdf");		
		logger.info("La chiamata e' arrivata dal seguente IP: " + (String) (MessageContext.getCurrentMessageContext()).getProperty(MessageContext.REMOTE_ADDR));
		
		SignedResponse toReturn = new SignedResponse();
		
		if(	(certname == null) || (certname.trim().equals("")))
		{
			Error error = new Error();
			error.setCode(2000);
			error.setDescription("Nessun nome del certificato da usare ricevuto in input alla request. Si prega di verificare.");
			toReturn.setError(error);
			return toReturn;
		}
		
		if(	(pin == null) || (pin.trim().equals("")))
		{
			Error error = new Error();
			error.setCode(2001);
			error.setDescription("Nessun pin del certificato ricevuto in input alla request. Si prega di verificare.");
			toReturn.setError(error);
			return toReturn;
		}
		
		if(	(buffer == null) || (buffer.length == 0))
		{
			Error error = new Error();
			error.setCode(2002);
			error.setDescription("Nessun buffer ricevuto in input alla request. Si prega di verificare.");
			toReturn.setError(error);
			return toReturn;
		}
		
		logger.info("Verifica parametri in input conclusa con successo e senza errori.");
		
		Security.addProvider(new BouncyCastleProvider());
		
		Properties properties = new Properties();
		
		try
		{
			properties.load(this.getClass().getResourceAsStream("/pdfservice.properties"));
		}
		catch (IOException e)
		{
			Error error = new Error();
			error.setCode(2010);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		
		logger.info("File di configurazione caricato correttamente");
		
		String certificatePath = properties.getProperty("certificate_path");
		
		if(
				(certificatePath != null) && 
				(!certificatePath.isEmpty())
			)
		{
			certificate = certificatePath+File.separator+certname;
		}
		else
		{
			certificate = certname;
		}
		
		logger.debug("Il certificato ricercato e' " + certificate);
		
		if(!new File(certificate).canRead())
		{
			Error error = new Error();
			error.setCode(2003);
			error.setDescription("Non risulta possibile leggere il file "+certificate+". Verificare che il file esista e si abbiano i permessi di lettura.");
			toReturn.setError(error);
			return toReturn;
		}
			
			
			
		KeyStore ks = null;
		try
		{
			ks = KeyStore.getInstance("PKCS12");
		} catch (KeyStoreException e)
		{
			Error error = new Error();
			error.setCode(2100);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		
		try
		{
			ks.load(new FileInputStream(certificate), pin.toCharArray());
		} catch (NoSuchAlgorithmException e)
		{
			Error error = new Error();
			error.setCode(2101);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (CertificateException e)
		{
			Error error = new Error();
			error.setCode(2102);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (IOException e)
		{
			Error error = new Error();
			error.setCode(2103);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		
		logger.info("Certificato di firma caricato correttamente");
	
		Enumeration<String> aliases = null;
		try
		{
			aliases = ks.aliases();
		}
		catch (KeyStoreException e)
		{
			Error error = new Error();
			error.setCode(2104);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
				
		Certificate cert1 = null;
		
		Certificate[] chain = null;
		
		PrivateKey pk = null;
		
		try
		{
			if(aliases.hasMoreElements()) 
			{
				String alias = (String) aliases.nextElement();
				
				cert1 = ks.getCertificate(alias);
				
				chain = ks.getCertificateChain(alias);
				
				pk = (PrivateKey) ks.getKey(alias, pin.toCharArray());

			}
		} 
		catch (KeyStoreException e)
		{
			Error error = new Error();
			error.setCode(2105);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		catch (UnrecoverableKeyException e)
		{
			Error error = new Error();
			error.setCode(2106);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		catch (NoSuchAlgorithmException e)
		{
			Error error = new Error();
			error.setCode(2107);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
        
		byte[] signedbuffer = null;
		
		if(isPades)
		{
			try
			{
				signedbuffer = innerPAdES(buffer, pk, cert1, chain);
			}
			catch (IOException e)
			{
				Error error = new Error();
				error.setCode(2200);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			}
			catch (DocumentException e)
			{
				Error error = new Error();
				error.setCode(2201);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			}
			catch (GeneralSecurityException e)
			{
				Error error = new Error();
				error.setCode(2202);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			}
		}
		
		if(isCades)
		{
			try
			{
				signedbuffer = innerCAdES(buffer, pk, cert1);
			}
			catch (InvalidKeyException e)
			{
				Error error = new Error();
				error.setCode(2203);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			}
			catch (NoSuchAlgorithmException e)
			{
				Error error = new Error();
				error.setCode(2204);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			}
			catch (NoSuchProviderException e)
			{
				Error error = new Error();
				error.setCode(2205);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			}
			catch (SignatureException e)
			{
				Error error = new Error();
				error.setCode(2206);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			}
			catch (CertificateEncodingException e)
			{
				Error error = new Error();
				error.setCode(2207);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			}
			catch (OperatorCreationException e)
			{
				Error error = new Error();
				error.setCode(2208);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			}
			catch (CMSException e)
			{
				Error error = new Error();
				error.setCode(2209);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			}
			catch (IOException e)
			{
				Error error = new Error();
				error.setCode(2210);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			}
		}
		
        logger.info("Buffer firmato correttamente con dimensioni di " + signedbuffer.length + " byte(s)");
        
        toReturn.setSignedPdf(signedbuffer);
        Error error = new Error();
		error.setCode(0);
		error.setDescription("OK");
        toReturn.setError(error);
        
        logger.info("Chiamata conclusa dal seguente IP: " + (String) (MessageContext.getCurrentMessageContext()).getProperty(MessageContext.REMOTE_ADDR) + " in " + (System.currentTimeMillis() - start) + " ms.");
        
		return toReturn;
	}
	
	
	
	
	private byte[] innerPAdES(byte[] buffer, PrivateKey pk, Certificate cert, Certificate[] chain) throws IOException, DocumentException, GeneralSecurityException
	{
		PdfReader reader = new PdfReader(buffer);

		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		
		PdfStamper stp = null;
        logger.debug("Creo la firma");
        stp = PdfStamper.createSignature(reader, bos, '\0', null, true);
        
        
        PdfSignatureAppearance sap = stp.getSignatureAppearance();
                
		sap.setCertificate(cert);
		
        sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
    	
		ExternalSignature es = new PrivateKeySignature(pk, "SHA-256", "BC");
        ExternalDigest digest = new BouncyCastleDigest();

		MakeSignature.signDetached(sap, digest, es, chain, null, null, null, 0, CryptoStandard.CMS);

		stp.close();

		return bos.toByteArray();
	}
	
	private byte[] innerCAdES(byte[] buffer, PrivateKey pk, Certificate cert) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, CertificateEncodingException, OperatorCreationException, CMSException, IOException
	{
		String hash = "SHA256withRSA";
		String provider = "BC";
//		
//		Signature signature = Signature.getInstance(hash, provider);
//		
//		signature.initSign(pk);
//		signature.update(buffer);
			
		//Build CMS
        X509Certificate x509cert = (X509Certificate) cert;
        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        CMSTypedData msg = new CMSProcessableByteArray(buffer); //signature.sign());
        certList.add(x509cert);
        Store certs = new JcaCertStore(certList);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder(hash).setProvider(provider).build(pk);
        gen.addSignerInfoGenerator(
        							new JcaSignerInfoGeneratorBuilder(
        																new JcaDigestCalculatorProviderBuilder().setProvider(provider).build()).build(sha1Signer, x509cert)
        							);
        gen.addCertificates(certs);
        CMSSignedData sigData = gen.generate(msg, true);
		
        
		return sigData.getEncoded();

	}
	
	
	/**
	 * Attiva il log della classe
	 * 
	 * @throws IOException
	 */
	private void activateLog() throws IOException
	{
		InputStream inputStream = this.getClass().getClassLoader()
				.getResourceAsStream("/log4j.properties");
		Properties properties = new Properties();
		properties.load(inputStream);
		PropertyConfigurator.configure(properties);
	}
}