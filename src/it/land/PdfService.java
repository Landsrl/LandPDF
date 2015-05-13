package it.land;


import it.land.responses.IsValidResponse;
import it.land.responses.SignedPdfResponse;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
 * @author Riccardo Bracci
 *
 */
public class PdfService
{

	private String certificate = null;

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
	 * Sign the pdf
	 * 
	 * @param certname Name of the P12 certificate
	 * @param pin Pin of the certificate
	 * @param pdf Buffer of the Pdf
	 * @return The response composed by an Error object (that has a status and reason) and the signed Pdf 
	 */
	public SignedPdfResponse sign(String certname, String pin, byte[] pdf)
	{
		SignedPdfResponse toReturn = new SignedPdfResponse();
		
		if(	(certname == null) || (certname.trim().equals("")))
		{
			Error error = new Error();
			error.setCode(2100);
			error.setDescription("Nessun nome del certificato da usare ricevuto in input alla request. Si prega di verificare.");
			toReturn.setError(error);
			return toReturn;
		}
		
		if(	(pin == null) || (pin.trim().equals("")))
		{
			Error error = new Error();
			error.setCode(2101);
			error.setDescription("Nessun pin del certificato ricevuto in input alla request. Si prega di verificare.");
			toReturn.setError(error);
			return toReturn;
		}
		
		if(	(pdf == null) || (pdf.length == 0))
		{
			Error error = new Error();
			error.setCode(2102);
			error.setDescription("Nessun pdf ricevuto in input alla request. Si prega di verificare.");
			toReturn.setError(error);
			return toReturn;
		}
		
		
		Security.addProvider(new BouncyCastleProvider());
		
		Properties properties = new Properties();
		
		try
		{
			properties.load(this.getClass().getResourceAsStream("/pdfservice.properties"));
		}
		catch (IOException e)
		{
			Error error = new Error();
			error.setCode(2001);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		
		String certificatePath = properties.getProperty("certificate_path");
		
		if(certificatePath != null)
		{
			certificate = certificatePath+File.separator+certname;
		}
		else
		{
			certificate = certname;
		}
			
			
			
		KeyStore ks = null;
		try
		{
			ks = KeyStore.getInstance("PKCS12");
		} catch (KeyStoreException e)
		{
			Error error = new Error();
			error.setCode(2002);
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
			error.setCode(2003);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (CertificateException e)
		{
			Error error = new Error();
			error.setCode(2004);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (IOException e)
		{
			Error error = new Error();
			error.setCode(2005);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
	
		Enumeration<String> aliases = null;
		try
		{
			aliases = ks.aliases();
		}
		catch (KeyStoreException e)
		{
			Error error = new Error();
			error.setCode(2006);
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
			error.setCode(2007);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		catch (UnrecoverableKeyException e)
		{
			Error error = new Error();
			error.setCode(2008);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		catch (NoSuchAlgorithmException e)
		{
			Error error = new Error();
			error.setCode(2009);
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
			error.setCode(2010);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		
		PdfStamper stp = null;
        try 
        {
        	System.out.println("Creo la firma");
        	stp = PdfStamper.createSignature(reader, bos, '\0', null, true);
        }
        catch (DocumentException e)
        {
        	Error error = new Error();
			error.setCode(2011);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
        }
        catch (IOException e)
        {
        	Error error = new Error();
			error.setCode(2012);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
        }
        
        PdfSignatureAppearance sap = stp.getSignatureAppearance();
                
		sap.setCertificate(cert1);
		
        sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
         
	
		
		ExternalSignature es = new PrivateKeySignature(pk, "SHA-256", "BC");
        ExternalDigest digest = new BouncyCastleDigest();
        try
		{
			MakeSignature.signDetached(sap, digest, es, chain, null, null, null, 0, CryptoStandard.CMS);
		}
		catch (IOException e)
		{
			Error error = new Error();
			error.setCode(2013);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		catch (DocumentException e)
		{
			Error error = new Error();
			error.setCode(2014);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		catch (GeneralSecurityException e)
		{
			Error error = new Error();
			error.setCode(2015);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		
        try
		{
        	
			stp.close();
		}
		catch (DocumentException e)
		{
			Error error = new Error();
			error.setCode(2016);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		catch (IOException e)
		{
			Error error = new Error();
			error.setCode(2017);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
        
		System.out.println("length: "+bos.toByteArray().length); 
		
        toReturn.setSignedPdf(bos.toByteArray());
        Error error = new Error();
		error.setCode(0);
		error.setDescription("OK");
        toReturn.setError(error);
        
        
		return toReturn;
	}
	

	
	/**
	 * Attiva il log della classe
	 * 
	 * @throws IOException
	 */
	private void activateLog() throws IOException
	{
		InputStream inputStream = this.getClass().getClassLoader()
				.getResourceAsStream("log4j.properties");
		Properties properties = new Properties();
		properties.load(inputStream);
		PropertyConfigurator.configure(properties);
	}
}