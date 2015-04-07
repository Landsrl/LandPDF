package it.land.responses;

import it.land.Error;

/**
 * 
 * @author Riccardo Bracci
 *
 */
public class IsValidResponse
{
	private boolean isSigned = false;
	private boolean isValid = false;
	private Error error = null;

	public boolean getIsSigned()
	{
		return isSigned;
	}

	public void setIsSigned(boolean isSigned)
	{
		this.isSigned = isSigned;
	}

	public void setIsValid(boolean isValid)
	{
		this.isValid = isValid;
	}

	public boolean getIsValid()
	{
		return isValid;
	}

	public Error getError()
	{
		return error;
	}

	public void setError(Error error)
	{
		this.error = error;
	}
}
