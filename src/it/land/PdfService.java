/*
 * --------------- Last change ------------------------
 * $HeadURL: http://svn:18080/svn/lexmark_apps/1/modules/LArchiveWSInterface/trunk/src/it/land/larchive/LArchiveClient.java $
 * $Id: LArchiveClient.java 39 2015-03-19 09:09:19Z rbracci $
 * $Date: 2015-03-19 10:09:19 +0100 (Thu, 19 Mar 2015) $
 * $Author: rbracci $
 * $Revision: 39 $
 * ----------------------------------------------------
 */
package it.land;

import it.land.responses.IsSignedResponse;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
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

	public static String ADOBE = "C:\\Users\\rbracci\\Desktop\\GeoTrust_Global_CA.pem";

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
//
//	public String testMethod(String param)
//	{
//		Logger.getLogger(getClass()).debug(param);
//		return "Read " + param;
//	}
//	
	public IsSignedResponse isSigned(String pdf)
	{
		IsSignedResponse toReturn = new IsSignedResponse();
		Date today = new Date();
		SimpleDateFormat dt1 = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss.SSS");
		String timestmp = dt1.format(today);
		String file = System.getProperty("java.io.tmpdir") + "pdftoelaborate"
				+ timestmp + ".pdf";
		try
		{
			byte dearr[] = DatatypeConverter.parseBase64Binary(pdf);
			FileOutputStream fos = new FileOutputStream(new File(file));
			fos.write(dearr);
			fos.close();
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
		Date today = new Date();
		SimpleDateFormat dt1 = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");
		String timestmp = dt1.format(today);
		String file = System.getProperty("java.io.tmpdir") + "pdftoelaborate"
				+ timestmp + ".pdf";
	
		
		try
		{
			byte dearr[] = DatatypeConverter.parseBase64Binary(pdf);
			FileOutputStream fos = new FileOutputStream(new File(file));
			fos.write(dearr);
			fos.close();
		} catch (Exception e)
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
			//if (errors.size() == 0)
				//out.println("Certificates verified against the KeyStore");
			//else
				//out.println(errors);
		}
		Error error = new Error();
		error.setCode(0);
		error.setDescription("OK");
		toReturn.setError(error);
		toReturn.setResponse(true);
		return toReturn;
	}
//
//	public IsSignedResponse hasValidSignature(String pdf)
//	{
//		IsSignedResponse toReturn = new IsSignedResponse();
//		Date today = new Date();
//		SimpleDateFormat dt1 = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");
//		String timestmp = dt1.format(today);
//		String file = System.getProperty("java.io.tmpdir") + "pdftoelaborate"
//				+ timestmp + ".pdf";
//		try
//		{
//			byte dearr[] = DatatypeConverter.parseBase64Binary(pdf);
//			FileOutputStream fos = new FileOutputStream(new File(file));
//			fos.write(dearr);
//			fos.close();
//		} catch (Exception e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		}
//
//		Security.addProvider(new BouncyCastleProvider());
//		PdfReader reader = null;
//		try
//		{
//			reader = new PdfReader(file);
//		} catch (IOException e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		}
//		KeyStore ks = null;
//		try
//		{
//			ks = KeyStore.getInstance(KeyStore.getDefaultType());
//		} catch (KeyStoreException e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		}
//		try
//		{
//			ks.load(null, null);
//		} catch (NoSuchAlgorithmException e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		} catch (CertificateException e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		} catch (IOException e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		}
//		CertificateFactory cf = null;
//		try
//		{
//			cf = CertificateFactory.getInstance("X.509");
//		} catch (CertificateException e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		}
//		try
//		{
//			ks.setCertificateEntry("adobe",
//					cf.generateCertificate(new FileInputStream(ADOBE)));
//		} catch (KeyStoreException e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		} catch (CertificateException e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		} catch (FileNotFoundException e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		}
//		CertificateVerifier custom = new CertificateVerifier(null)
//		{
//			public List<VerificationOK> verify(X509Certificate signCert,
//					X509Certificate issuerCert, Date signDate)
//					throws GeneralSecurityException, IOException
//			{
//				System.out.println(signCert.getSubjectDN().getName()
//						+ ": ALL VERIFICATIONS DONE");
//				return new ArrayList<VerificationOK>();
//			}
//		};
//		LtvVerifier data = null;
//		try
//		{
//			data = new LtvVerifier(reader);
//		} catch (GeneralSecurityException e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		}
//		data.setRootStore(ks);
//		data.setCertificateOption(CertificateOption.WHOLE_CHAIN);
//		data.setVerifier(custom);
//		data.setOnlineCheckingAllowed(false);
//		data.setVerifyRootCertificate(false);
//		List<VerificationOK> list = new ArrayList<VerificationOK>();
//		System.out.println("PRE VERIFICATION");
//		try
//		{
//			data.verify(list);
//		} catch (GeneralSecurityException e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		} catch (IOException e)
//		{
//			Error error = new Error();
//			error.setCode(3);
//			error.setDescription(e.getMessage());
//			toReturn.setError(error);
//			return toReturn;
//		}
//		if (list.size() == 0)
//		{
//			System.out.println("The document can't be verified");
//		}
//		for (VerificationOK v : list)
//			System.out.println(v.toString());
//
//		Error error = new Error();
//		error.setCode(0);
//		error.setDescription("OK");
//		toReturn.setError(error);
//		toReturn.setResponse(true);
//		return toReturn;
//	}

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

//	public void verifySignatures() throws GeneralSecurityException,
//			IOException
//	{
//		Security.addProvider(new BouncyCastleProvider());
//		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
//		ks.load(null, null);
//		CertificateFactory cf = CertificateFactory.getInstance("X509");
//		FileInputStream is1 = new FileInputStream(ADOBE);
//		X509Certificate cert1 = (X509Certificate) cf.generateCertificate(is1);
//		ks.setCertificateEntry("cacert", cert1);
//		PrintWriter out = new PrintWriter(new FileOutputStream(VERIFICATION));
//		PdfReader reader = new PdfReader(SIGNED2);
//		AcroFields af = reader.getAcroFields();
//		ArrayList<String> names = af.getSignatureNames();
//		for (String name : names)
//		{
//			out.println("Signature name: " + name);
//			out.println("Signature covers whole document: "
//					+ af.signatureCoversWholeDocument(name));
//			out.println("Document revision: " + af.getRevision(name) + " of "
//					+ af.getTotalRevisions());
//			PdfPKCS7 pk = af.verifySignature(name);
//			System.out.println(String.format("Checking %ssignature %s", pk.isTsp() ? "document-level timestamp " : "", name));
//			Calendar cal = pk.getSignDate();
//			out.println("cal: " + cal.getTimeInMillis());
//			Certificate[] pkc = pk.getCertificates();
//			out.println("Subject: "
//					+ CertificateInfo.getSubjectFields(pk
//							.getSigningCertificate()));
//			out.println("Revision modified: " + !pk.verify());
//			List<VerificationException> errors = CertificateVerification
//					.verifyCertificates(pkc, ks, null, cal);
//			if (errors.size() == 0)
//				out.println("Certificates verified against the KeyStore");
//			else
//				out.println(errors);
//		}
//		out.flush();
//		out.close();
//	}
}