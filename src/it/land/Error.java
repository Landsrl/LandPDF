package it.land;

/**
 * 
 * @author Riccardo Bracci
 *
 */
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