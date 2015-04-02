/*
 * --------------- Last change ------------------------
 * $HeadURL: http://svn:18080/svn/ValiWEB/1/modules/GestioneFirme/trunk/src/it/land/controller/Firma.java $
 * $Id: Firma.java 49 2015-02-04 15:16:48Z rbracci $
 * $Date: 2015-02-04 16:16:48 +0100 (Wed, 04 Feb 2015) $
 * $Author: rbracci $
 * $Revision: 49 $
 * ----------------------------------------------------
 */
package it.land;

public class Error
{

	private int code = 0;
	private String description = null;

	public int getCode()
	{
		return code;
	}

	public void setCode(int code)
	{
		this.code = code;
	}

	public String getDescription()
	{
		return description;
	}

	public void setDescription(String description)
	{
		this.description = description;
	}
}