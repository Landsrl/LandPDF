package it.land.responses;

import it.land.Error;

public class IsSignedResponse
{
	private boolean response = false;
	private Error error = null;

	public boolean getResponse()
	{
		return response;
	}

	public void setResponse(boolean response)
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
