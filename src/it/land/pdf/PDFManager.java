/**
 * @author mcosta
 *
 */
package it.land.pdf;



import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Random;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Element;
import com.itextpdf.text.Phrase;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.BaseFont;
import com.itextpdf.text.pdf.ColumnText;
import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfFileSpecification;
import com.itextpdf.text.pdf.PdfFormField;
import com.itextpdf.text.pdf.PdfLayer;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.TextField;





/**
 * @author mcosta
 *
 */
public class PDFManager
{
	private ByteArrayOutputStream stream = null;
	
	private PdfStamper stamper = null;
	
	private PdfReader reader = null;
	
	private static float TEXTFIELD_HEIGHT = 30;	
	
	private static float TEXTFIELD_WIDTH = 300;
	
	/**
	 * @throws PDFManagerException 
	 * 
	 */
	public PDFManager(byte[] pdfbuffer) throws PDFManagerException
	{
		stream = new ByteArrayOutputStream();
		
		try
		{
			reader = new PdfReader(pdfbuffer);
			stamper = new PdfStamper(reader, stream, '\0', true);
		}
		catch (IOException e)
		{
			throw new PDFManagerException("Errore durante la lettura del pdf. " + e.getMessage());
		}
		catch (DocumentException e)
		{
			throw new PDFManagerException("Errore durante la verifica del pdf. " + e.getMessage());
		}
	}
	
	
	/**
	 * Aggiunge un allegato al pdf ricevuto in input alla classe
	 * 
	 * @param attachment L'allegato da inserire
	 * @param name Il nome da dare all'allegato
	 * 
	 * @return Il pdf arricchito con l'allegato
	 * @throws PDFManagerException Nel caso in cui si verifichino problemi durante l'inserimento dell'allegato
	 */
	public void addAttachment(byte[] attachment, String name) throws PDFManagerException
	{
		
		
		try
		{
			
			PdfFileSpecification fs = PdfFileSpecification.fileEmbedded(       		
															            stamper.getWriter(), 
															            null, 
															            name,
															            attachment
															            );
			stamper.addFileAttachment(name, fs);
		}
		catch (IOException e)
		{
			throw new PDFManagerException("Errore durante l'inserimento dell'allegato nel pdf. " + e.getMessage());
		}


	}
	
	
	
	
	/**
	 * Inserisce il testo come layer nel pdf ricevuto in input alla classe
	 * 
	 * @param labelform Nome del layer
	 * @param labeltext Testo da inserire nel form
	 * @param x La posizione x del testo
	 * @param y La posizione y del testo
	 * @param rotation La rotazione da applicare in gradi (in senso orario) 
	 * 
	 * @return Il pdf arricchito del layer con il testo
	 * @throws PDFManagerException Nel caso in cui si verifichino problemi durante l'inserimento del testo come layer
	 */
	public void addForm(String labelform, String labeltext, float x, float y, float rotation, int page) throws PDFManagerException
	{

		//PdfWriter writer = stamper.getWriter();
		
//		TextField file = new TextField(
//											stamper.getWriter(), 
//											new Rectangle(
//															36, 
//															500, 
//															360, 
//															530),
//														 
//											"myfile");
//        file.setOptions(TextField.FILE_SELECTION);
        try
		{
//			PdfFormField upload = file.getTextField();
//			upload.setAdditionalActions(
//											PdfName.U,
//											PdfAction.javaScript(
//												"this.getField('myfile').browseForFileToSubmit();"
//												+ "this.getField('mytitle').setFocus();",
//											stamper.getWriter()));
//			stamper.addAnnotation(upload, 1);
        	
        	
        	//la lunghezza della text field e' data al punto iniziale "x" + i pixel di lunghezza che gli si vuole dare
        	float width = x + TEXTFIELD_WIDTH;
        	
        	//l'altezza della text field e' data al punto iniziale "y" + i pixel di altezza che gli si vuole dare
        	float height = y + TEXTFIELD_HEIGHT;
        	
			TextField formfield = new TextField(
												stamper.getWriter(), 
												new Rectangle(
																x, 
																y, 
																width, 
																height), 
												labelform);
			
			
			formfield.setOptions(PdfFormField.FF_READ_ONLY);
			formfield.setText(labeltext);
			

			stamper.addAnnotation(formfield.getTextField(), page);
			
		}
		catch (IOException e)
		{
			throw new PDFManagerException("Errore durante la lettura del pdf per l'inserimento dei form. " + e.getMessage());
		}
		catch (DocumentException e)
		{
			throw new PDFManagerException("Errore durante la modifica del pdf per l'inserimento dei form. " + e.getMessage());
		}

	}
	
	
	
	public void fillForm(String formname, String formvalue) throws PDFManagerException
	{
		try
		{
			AcroFields form = stamper.getAcroFields();
		    boolean isFilled = form.setField(formname, formvalue);
		    form.setFieldProperty(formname, "setfflags", PdfFormField.FF_READ_ONLY, null);
		    
		    if(!isFilled)
		    {
		    	Logger.getLogger(getClass()).warn("Attenzione! Form " + formname + " non valorizzato con il valore " + formvalue + ". Verificare la correttezza dei dati.");
		    }
		}
		catch (IOException e)
		{
			throw new PDFManagerException("Errore durante la lettura del pdf per l'inserimento dei form. " + e.getMessage());
		}
		catch (DocumentException e)
		{
			throw new PDFManagerException("Errore durante la modifica del pdf per l'inserimento dei form. " + e.getMessage());
		}
       

	}
	
	
	/**
	 * Inserisce il testo come layer nel pdf ricevuto in input alla classe
	 * 
	 * @param layername Nome del layer
	 * @param text Il testo da inserire
	 * @param x La posizione x del testo
	 * @param y La posizione y del testo
	 * @param rotation La rotazione da applicare in gradi (in senso orario) 
	 * 
	 * @return Il pdf arricchito del layer con il testo
	 * @throws PDFManagerException Nel caso in cui si verifichino problemi durante l'inserimento del testo come layer
	 */
	public void addText(String layername, String text, float x, float y, float rotation) throws PDFManagerException
	{
		

		BaseFont bf = null;
		try
		{
			bf = BaseFont.createFont();
		}
		catch (DocumentException e)
		{
			throw new PDFManagerException("Errore durante la creazione del font per lo specchietto. " + e.getMessage());
		}
		catch (IOException e)
		{
			throw new PDFManagerException("Errore durante la creazione del font per lo specchietto. " + e.getMessage());
		}                             
		
		PdfContentByte cb = stamper.getOverContent(1);
		
		PdfLayer layer = null;
		try
		{
			layer = new PdfLayer(
											layername, 	//nome del layer
											stamper.getWriter()
										);
		}
		catch (IOException e)
		{
			throw new PDFManagerException(e.getMessage());
		}
		
		layer.setOn(true);
		
		
		cb.setFontAndSize(bf, 18);
		
	
		cb.beginLayer(layer);
		
		ColumnText.showTextAligned(
									cb, 
									Element.ALIGN_LEFT, 
									new Phrase(text), 	//testo del layer
									x, 
									y, 
									rotation);
		
		cb.endLayer();


	}
	
	
	
	
	
	/**
	 * Calcola l'ID iniziale e finale del PDF.
	 * Per ricavare gli id, utilizzare gli appositi metodi "getOriginalID" e "getLastID"
	 * @param pdf Lo stream del pdf
	 * @throws PDFManagerException Nel caso in cui si verifichino problemi durante il calcolo dell'ID
	 */
	public byte[] calculateIDs() throws PDFManagerException
	{
		String originalID;
		
		String lastID;
		
		int NUM_CHAR_HEX_ID = 32;
		

	    PdfDictionary trailer = reader.getTrailer();
	    
	    if (trailer.contains(PdfName.ID)) 
	    {
	        PdfArray ids = (PdfArray) trailer.get(PdfName.ID);
	        
	        System.out.println("id length: " + ids.size());
	        
	        PdfString original = ids.getAsString(0);
	        PdfString modified = ids.getAsString(1);
	        
	        originalID = new String(Hex.encodeHex(original.getBytes()));
	        lastID = new String(Hex.encodeHex(modified.getBytes()));
	        
	        
	        System.out.println("OriginalID: " +  originalID);
	        
	        System.out.println("last: " +  lastID);
	    }
	    else
	    {
	    	System.out.println("generato da codice");
	    	//String hex = getRandomHexString(NUM_CHAR_HEX_ID);
	    	originalID = getRandomHexString(NUM_CHAR_HEX_ID);	//hex;
	    	lastID = getRandomHexString(NUM_CHAR_HEX_ID);			//hex;
	    	
	    	PdfArray ids = new PdfArray();
	    	
	    	ids.add(0, new PdfString (originalID));
	    	
	    	
	    	ids.add(1, new PdfString (lastID));
	    	
	    	
	    	trailer.put(PdfName.ID, ids);
	    	
	    	
	    	System.out.println("OriginalID: " +  originalID);
	        
	        System.out.println("last: " +  lastID);
	    }
		    	    
        
        
        return stream.toByteArray();
        
	}
	
	
	/**
	 * Genera una stringa esadecimale random
	 * @param numchars numero di caratteri che formeranno la stringa
	 * @return L'esadecimale creato random
	 */
	private String getRandomHexString(int numchars)
	{
        Random r = new Random();
        StringBuffer sb = new StringBuffer();
        while(sb.length() < numchars){
            sb.append(Integer.toHexString(r.nextInt()));
        }

        return sb.toString().substring(0, numchars);
	}



	public void closePdf()
	{
		
		if(stamper != null)
		{
			try
			{                                                               
				stamper.close();
			}
			catch (Exception e)
			{
				Logger.getLogger(getClass()).warn("Errore durante la chiusura del pdf. " + e.getMessage());
			}
		}
		
		if(reader != null)
	    {
	    	reader.close();
	    }
	}
	
	public byte[] getUpdatedPdf()
	{
		closePdf();
		
		
		return stream.toByteArray();
	}
	
	
	
	public int getNumberOfPages()
	{
		return reader.getNumberOfPages();
	}
}
