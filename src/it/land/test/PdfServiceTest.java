package it.land.test;

import static org.junit.Assert.assertNotNull;
import it.land.PdfService;
import it.land.responses.IsSignedResponse;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
		String SIGNED2 = "C:\\Users\\rbracci\\Desktop\\BUDGET-2013-BUD.pdf";
		String base64 = null;
		try
		{
			FileInputStream fis = new FileInputStream(new File(SIGNED2));
			byte[] bytes = IOUtils.toByteArray(fis);
			base64 = DatatypeConverter.printBase64Binary(bytes);
		} catch (FileNotFoundException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(System.getProperty("java.io.tmpdir"));
		
		PdfService service = new PdfService();
		IsSignedResponse test2 = service.isValid(base64);
		System.out.println(test2.getResponse());
		System.out.println(test2.getError().getCode() + ""+ test2.getError().getDescription());
		assertNotNull(test2);
	}

}
