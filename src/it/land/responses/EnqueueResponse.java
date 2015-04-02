/*
 * --------------- Last change ------------------------
 * $HeadURL: http://svn:18080/svn/ValiWEB/1/modules/GestioneFirme/trunk/src/it/land/controller/Firma.java $
 * $Id: Firma.java 49 2015-02-04 15:16:48Z rbracci $
 * $Date: 2015-02-04 16:16:48 +0100 (Wed, 04 Feb 2015) $
 * $Author: rbracci $
 * $Revision: 49 $
 * ----------------------------------------------------
 */
package it.land.responses;


import it.land.Error;

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
