package yetmorecode.ghidra.lx.loader;

import java.io.IOException;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
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
public class LxLoader extends LinearLoader {

	@Override
	public String getName() {
		return "Linear Executable (LX-Style OS/2)";
	}

	@Override
	public void checkFormat(FactoryBundledWithBinaryReader reader) throws IOException, InvalidHeaderException {
    	// Try parsing MZ header
        var mzHeader = DOSHeader.createDOSHeader(reader);
        var lfanew = 0;
        if (mzHeader.isDosSignature()) {
        	 lfanew = mzHeader.e_lfanew();
        }
        // Try parsing LX Header
    	var header = new Header(reader, (short) lfanew);
    	if (!header.isLx()) {
    		throw new InvalidHeaderException("Not LX-Style");
    	}
	}
	
	@Override
	public void onLoadSuccess(Program program) {
		Msg.info(this, String.format("Succesfully loaded %s (LX-Style)", program.getDomainFile()));
	}
}
