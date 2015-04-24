package it.land.test;

import static org.junit.Assert.assertNotNull;
import it.land.PdfService;
import it.land.responses.IsValidResponse;

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
		byte[] bytes = null;
		try
		{
			FileInputStream fis = new FileInputStream(new File(SIGNED2));
			bytes = IOUtils.toByteArray(fis);
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

		PdfService service = new PdfService();
		IsValidResponse test = service.isValid(bytes);
		System.out.println(test.getIsSigned());
		System.out.println(test.getIsValid());
		System.out.println(test.getError().getCode() + ""
				+ test.getError().getDescription());

		assertNotNull(test);
	}

}
