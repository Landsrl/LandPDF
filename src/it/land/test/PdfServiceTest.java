package it.land.test;

import static org.junit.Assert.assertNotNull;
import it.land.PdfService;
import it.land.responses.IsValidResponse;
import it.land.responses.SignedPdfResponse;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

/**
 * 
 * @author Riccardo Bracci
 *
 */
public class PdfServiceTest
{

	@Test
	public void testTestMethod()
	{
		String SIGNED2 = "data/signed.pdf";//"C:\\Users\\rbracci\\Desktop\\BUDGET-2013-BUD.pdf";
		byte[] bytes = null;
		try
		{
			FileInputStream fis = new FileInputStream(new File(SIGNED2));
			bytes = IOUtils.toByteArray(fis);
		} catch (FileNotFoundException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		PdfService service = new PdfService();
		IsValidResponse test = service.isValid(bytes);
		System.out.println(test.getIsSigned());
		System.out.println(test.getIsValid());
		System.out.println(test.getError().getCode() + ":"
				+ test.getError().getDescription());

		assertNotNull(test);
	}
	
	
	
	@Test
	public void testSignPdfMethod()
	{
		
		
		PdfService service = new PdfService();
		
		String certname = "data/test.p12";
		
		System.out.println("Esiste il file "+certname+"? "+new File(certname).exists());
		
		String pin = "password";
		
		byte[] pdf = null;
		
		String filename = "data/test.pdf";
		
		try
		{
			FileInputStream fis = new FileInputStream(new File(filename));
			
			System.out.println("Esiste il file "+filename+"? "+new File(filename).exists());
			
			
			pdf = IOUtils.toByteArray(fis);
		} catch (FileNotFoundException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
		SignedPdfResponse response = service.sign(certname, pin, pdf);
		
		byte[] signed = response.getSignedPdf();
		
		System.out.println("Code: "+response.getError().getCode());
		
		System.out.println("Message: "+response.getError().getDescription());

		if(response.getError().getCode() == 0)
		{
			try
			{
				System.out.println("Signed length: "+signed.length+" byte(s)");
				
				FileOutputStream fos = new FileOutputStream("data/signed.pdf");
				
				fos.write(signed);
				
				fos.flush();
				
				fos.close();
			}
			catch (FileNotFoundException e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			catch (IOException e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
	}

}
