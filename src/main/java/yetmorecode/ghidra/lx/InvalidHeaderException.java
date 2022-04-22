package yetmorecode.ghidra.lx;

/**
 * An exception class to handle encountering
 * invalid LX/LE Headers.
 */
public class InvalidHeaderException extends Exception {
	private static final long serialVersionUID = 1L;
	
	public InvalidHeaderException(String message) {
		super(message);
	}
}