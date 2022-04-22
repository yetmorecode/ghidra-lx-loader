package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import yetmorecode.file.format.lx.LinearExecutable;
import yetmorecode.file.format.lx.LinearObjectTableEntry;
import yetmorecode.ghidra.lx.InvalidHeaderException;
import yetmorecode.ghidra.lx.Options;


public class Executable extends LinearExecutable {
    private FactoryBundledWithBinaryReader reader;
    
    public boolean isUnbound = false;
    
    // MZ header
    public DOSHeader mz;
    
    // DOS/16 headers
    public HashMap<Long, Dos16Header> dos16Headers =  new HashMap<Long, Dos16Header>();
    public DOSHeader mzSecondary;
    
    // When there is no MZ header (i.e. unbound LE-Style executables), the new file header starts at 0
    public long lfanew = 0;
    public long lfamz = 0;
    
	public Executable(GenericFactory factory, ByteProvider bp, Options options) throws IOException, InvalidHeaderException {
    	reader = new FactoryBundledWithBinaryReader(factory, bp, true);
    	try {
	    	// Try reading MZ header
	        mz = DOSHeader.createDOSHeader(reader);
	        if (mz.isDosSignature()) {
	        	if (mz.e_lfarlc() == 0x40) {
	        		// New exe style (with e_lfanew)
	        		lfanew = mz.e_lfanew();
	        	} else {
	        		// Old exe style (without e_lfanew)
	        		long secondaryOffset = (mz.e_cp()-1)*512 + mz.e_cblp();
	        		Dos16Header bwHeader;
	        		try {
	        			do {
	        				bwHeader = new Dos16Header(reader, secondaryOffset);
	        				dos16Headers.put(secondaryOffset, bwHeader);
	        				secondaryOffset = bwHeader.next_header_pos;
	        			} while (secondaryOffset > 0);
	        		} catch (InvalidHeaderException exception) {
	        			// Done walking BW headers
	        		}
	        		reader.setPointerIndex(secondaryOffset);
	        		mzSecondary = DOSHeader.createDOSHeader(reader);
	        		lfamz = secondaryOffset;
	        		lfanew = secondaryOffset + mzSecondary.e_lfanew();
	        	}
	        }
    	} catch (Exception e) {}
    	
    	// LX header
    	header = new Header(reader, lfanew);
    	
    	// Object record table
    	for (int object = 0; object < header.objectCount; object++) {
    		objects.add(new ObjectTableEntry(this, object));
    	}
    	
    	// Page record table
    	for (int page = 0; page < header.pageCount; page++) {
    		if (header.isLe()) {
    			pageRecords.add(new LePageMapEntry(this, page));	
    		} else {
    			pageRecords.add(new LxPageMapEntry(this, page));
    		}
    		
    	}
    	
    	// Read fixup page table
    	fixupTable = new long[header.pageCount+1];
    	var tableOffset = lfanew + header.fixupPageTableOffset;
    	for (int i = 0; i <= header.pageCount; i++) {
    		fixupTable[i] = getReader().readInt(tableOffset + i * 4);
    	}
    	
    	// Read fixups
    	var fixupRecordOffset = lfanew + header.fixupRecordTableOffset;
    	fixupCount = 0;
    	for (var object : objects) {
    		for (int i = 0; i < object.pageCount; i++) {
    			var page = object.pageTableIndex + i;
        		fixups.put(page, new ArrayList<>());
        		var fixupBegin = getFixupBegin(page);
        		var fixupEnd = getFixupEnd(page);
        		var fixupDataSize = fixupEnd - fixupBegin;
        		var current = 0;
    			while (current < fixupDataSize) {
    				var fixup = new FixupRecord(
						reader, 
						fixupRecordOffset + fixupBegin + current, 
						++fixupCount, 
						options.getBaseAddress(object),
						i
    				);
    				fixups.get(page).add(fixup);
    				current += fixup.size;
    			}
    		}
    	}
    }
	
    /**
     * Returns the underlying binary reader.
     * @return the underlying binary reader
     */
    public FactoryBundledWithBinaryReader getBinaryReader() {
        return reader;
    }

    public FactoryBundledWithBinaryReader getReader() {
		return reader;
	}

	public long getFixupBegin(int page) {
		return fixupTable[page-1];
	}
	
	public long getFixupEnd(int page) {
		return fixupTable[page];
	}
	
	public int totalFixups() {
		int total = 0;
		for (var i = 1; i <= header.pageCount; i++) {
			total += fixups.get(i).size();
		}
		return total;
	}
	
	public boolean objectHasFixups(LinearObjectTableEntry object) {
		var total = 0;
		for (int i = 0; i < object.pageCount; i++) {
			var page = object.pageTableIndex + i;
			total += getFixupEnd(page) - getFixupBegin(page);
		}
		return total > 0;
	}
}

