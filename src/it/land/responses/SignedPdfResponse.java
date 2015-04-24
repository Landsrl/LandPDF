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
public class SignedPdfResponse
{
	private byte[] signedPdf = null;
	
	private Error error = null;

	/**
	 * @return the signedPdf
	 */
	public byte[] getSignedPdf()
	{
		return signedPdf;
	}

	/**
	 * @param signedPdf the signedPdf to set
	 */
	public void setSignedPdf(byte[] signedPdf)
	{
		this.signedPdf = signedPdf;
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
