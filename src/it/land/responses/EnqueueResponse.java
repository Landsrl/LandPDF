package it.land.responses;


import it.land.Error;

/**
 * 
 * @author Riccardo Bracci
 *
 */
public class EnqueueResponse
{

	private String response = null;
	private Error error = null;

	public String getResponse()
	{
		return response;
	}

	public void setResponse(String response)
	{
		this.response = response;
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
