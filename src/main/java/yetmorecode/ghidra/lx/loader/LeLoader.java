package yetmorecode.ghidra.lx.loader;

import java.io.IOException;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import yetmorecode.file.format.lx.LinearHeader;
import yetmorecode.ghidra.format.lx.model.DOSHeader;
import yetmorecode.ghidra.format.lx.model.Dos16Header;
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
public class LeLoader extends LinearLoader {

	@Override
	public String getName() {
		return "Linear Executable (LE-Style DOS)";
	}

	@Override
	public void checkFormat(FactoryBundledWithBinaryReader reader) throws IOException, InvalidHeaderException {
    	// Try parsing MZ header
		reader.setPointerIndex(0);
        var mzHeader = DOSHeader.createDOSHeader(reader);
        long lfanew = 0;
        if (mzHeader.isDosSignature()) {
        	if (mzHeader.e_lfarlc() == 0x40) {
        		// New exe style (with e_lfanew)
        		lfanew = mzHeader.e_lfanew();
        	} else {
        		// Old exe style (without e_lfanew)
        		long secondaryOffset = (mzHeader.e_cp()-1)*512 + mzHeader.e_cblp();
        		Dos16Header bwHeader;
        		try {
        			do {
        				bwHeader = new Dos16Header(reader, secondaryOffset);
        				secondaryOffset = bwHeader.next_header_pos;
        			} while (secondaryOffset > 0);
        		} catch (InvalidHeaderException exception) {
        			// Done walking BW headers
        		}
        		
        		reader.setPointerIndex(secondaryOffset);
        		var dos2 = DOSHeader.createDOSHeader(reader);
        		lfanew = secondaryOffset + dos2.e_lfanew();
        	}
        }
        
        // Try parsing LX Header
    	var header = new Header(reader, lfanew);
    	if (!header.isLe()) {
    		throw new InvalidHeaderException("Not LE-Style");
    	}

    	if ((header.moduleFlags & LinearHeader.MODULE_TYPE_MASK) == LinearHeader.MODULE_VXD) {
        	// Guess VxD from module type and missing eip
    		throw new InvalidHeaderException("Let VxD Loader handle it");
    	}
	}
	
	@Override
	public void onLoadSuccess(Program program) {
		Msg.info(this, String.format("Succesfully loaded %s (LE-Style)", program.getDomainFile()));
	}
	
}
