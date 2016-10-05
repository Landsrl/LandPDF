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
public class SignedResponse
{
	private byte[] signed = null;
	
	private Error error = null;

	/**
	 * @return the signed
	 */
	public byte[] getSigned()
	{
		return signed;
	}

	/**
	 * @param signed the signed to set
	 */
	public void setSigned(byte[] signed)
	{
		this.signed = signed;
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
