package it.land;

import it.land.responses.IsSignedResponse;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Properties;

import javax.xml.bind.DatatypeConverter;

import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.LtvVerifier;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.VerificationException;

/**
 * 
 * @author Riccardo Bracci
 *
 */
public class PdfService
{

	private String ADOBE = null;

	public PdfService()
	{
		try
		{
			activateLog();
		} catch (IOException e)
		{
			System.out.println(e.getMessage());
		}
		ADOBE = this.getClass().getClassLoader()
				.getResource("GeoTrust_CA_for_Adobe.pem").getPath();
	}
	
	public IsSignedResponse isSigned(String pdf)
	{
		IsSignedResponse toReturn = new IsSignedResponse();
		byte file[] = null;
		try
		{
			file = DatatypeConverter.parseBase64Binary(pdf);
		} catch (Exception e)
		{
			Error error = new Error();
			error.setCode(1);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}

		Security.addProvider(new BouncyCastleProvider());
		PdfReader reader = null;
		try
		{
			reader = new PdfReader(file);
		} catch (IOException e)
		{
			Error error = new Error();
			error.setCode(2);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		KeyStore ks = null;
		try
		{
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e)
		{
			Error error = new Error();
			error.setCode(3);
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
			error.setCode(4);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (CertificateException e)
		{
			Error error = new Error();
			error.setCode(5);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (IOException e)
		{
			Error error = new Error();
			error.setCode(2);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		CertificateFactory cf = null;
		try
		{
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e)
		{
			Error error = new Error();
			error.setCode(6);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		try
		{
			ks.setCertificateEntry("adobe",
					cf.generateCertificate(new FileInputStream(ADOBE)));
		} catch (KeyStoreException e)
		{
			Error error = new Error();
			error.setCode(3);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (CertificateException e)
		{
			Error error = new Error();
			error.setCode(6);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (FileNotFoundException e)
		{
			Error error = new Error();
			error.setCode(7);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}

		try
		{
			LtvVerifier data = new LtvVerifier(reader);
		} catch (GeneralSecurityException e)
		{
			Error error = new Error();
			error.setCode(8);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (Exception e)
		{
			Error error = new Error();
			error.setCode(8);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		Error error = new Error();
		error.setCode(0);
		error.setDescription("OK");
		toReturn.setError(error);
		toReturn.setResponse(true);
		return toReturn;
	}

	public IsSignedResponse isValid(String pdf)
	{
		IsSignedResponse toReturn = new IsSignedResponse();
		byte file[] = null;
		try
		{
			file = DatatypeConverter.parseBase64Binary(pdf);
		}catch (Exception e)
		{
			Error error = new Error();
			error.setCode(1);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		Security.addProvider(new BouncyCastleProvider());
		KeyStore ks = null;
		try
		{
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e)
		{
			Error error = new Error();
			error.setCode(1);
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
			error.setCode(2);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (CertificateException e)
		{
			Error error = new Error();
			error.setCode(3);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		} catch (IOException e)
		{
			Error error = new Error();
			error.setCode(4);
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
			error.setCode(5);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		FileInputStream is1 = null;
		try
		{
			is1 = new FileInputStream(ADOBE);
		} catch (FileNotFoundException e)
		{
			Error error = new Error();
			error.setCode(6);
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
			error.setCode(7);
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
			error.setCode(8);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		PdfReader reader = null;
		try
		{
			reader = new PdfReader(file);
		} catch (IOException e)
		{
			Error error = new Error();
			error.setCode(9);
			error.setDescription(e.getMessage());
			toReturn.setError(error);
			return toReturn;
		}
		AcroFields af = reader.getAcroFields();
		ArrayList<String> names = af.getSignatureNames();
		for (String name : names)
		{
			PdfPKCS7 pk = af.verifySignature(name);
			Calendar cal = pk.getSignDate();
			Certificate[] pkc = pk.getCertificates();
			List<VerificationException> errors = CertificateVerification
					.verifyCertificates(pkc, ks, null, cal);
			X509Certificate cert = (X509Certificate) pk.getSigningCertificate();
			try
			{
				cert.checkValidity();
			} catch (CertificateExpiredException e)
			{
				Error error = new Error();
				error.setCode(10);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			} catch (CertificateNotYetValidException e)
			{
				Error error = new Error();
				error.setCode(11);
				error.setDescription(e.getMessage());
				toReturn.setError(error);
				return toReturn;
			}
			// if (errors.size() == 0)
			// out.println("Certificates verified against the KeyStore");
			// else
			// out.println(errors);
		}
		Error error = new Error();
		error.setCode(0);
		error.setDescription("OK");
		toReturn.setError(error);
		toReturn.setResponse(true);
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