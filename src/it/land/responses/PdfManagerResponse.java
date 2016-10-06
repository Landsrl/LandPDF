/**
 * @author mcosta
 *
 */
package it.land.responses;

import it.land.Error;

/**
 * @author mcosta
 *
 */
public class PdfManagerResponse
{

	private byte[] updatedPdf = null;
	
	
	private Error error = null;

	/**
	 * @return the updatedPdf
	 */
	public byte[] getUpdatedPdf()
	{
		return updatedPdf;
	}

	/**
	 * @param updatedPdf the updatedPdf to set
	 */
	public void setUpdatedPdf(byte[] updatedPdf)
	{
		this.updatedPdf = updatedPdf;
	}

	/**
	 * @return the error
	 */
	public Error getError()
	{
		return error;
	}

	/**
	 * @param error the error to set
	 */
	public void setError(Error error)
	{
		this.error = error;
	}
	
	
}
