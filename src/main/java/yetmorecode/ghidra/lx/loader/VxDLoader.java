package yetmorecode.ghidra.lx.loader;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import yetmorecode.ghidra.format.lx.model.Header;
import yetmorecode.ghidra.lx.InvalidHeaderException;
import yetmorecode.ghidra.lx.LinearLoader;

/**
 * LxLoader - LX/LE/LC executable format loader
 * 
 * This loader is able to to load executable files of the LX/LE/LC format.
 * 
 * Linear Executable is an executable file format. 
 * It is used by OS/2, MS-DOS (DOS extender), and by MS Windows VxD files. 
 * It is a successor to NE (New Executable). 
 * There are two main varieties of it: LX (32-bit), and LE (mixed 16/32-bit).
 * LC variety is using compression (hence the C).
 * 
 * @author yetmorecode@posteo.net
 */
public class VxDLoader extends LinearLoader {

	@Override
	public String getName() {
		return "Linear Executable (LE-Style Windows VxD)";
	}

	@Override
	public void checkFormat(BinaryReader reader) throws IOException, InvalidHeaderException {
		// Try parsing MZ header
        var mzHeader = new DOSHeader(reader);
        var lfanew = 0;
        if (mzHeader.isDosSignature()) {
        	 lfanew = mzHeader.e_lfanew();
        }
        // Try parsing LX Header
    	var header = new Header(reader, (short) lfanew);
    	if (!header.isVxD()) {
    		throw new InvalidHeaderException("Not VxD LE-Style");
    	}
	}

	@Override
	public void onLoadSuccess(Program program) {
		Msg.info(this, String.format("Succesfully loaded %s (VxD LE-Style)", program.getDomainFile()));
	}
}
