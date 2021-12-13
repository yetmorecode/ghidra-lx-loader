package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.mz.DOSHeader;
import yetmorecode.ghidra.format.lx.InvalidHeaderException;
import yetmorecode.ghidra.format.lx.LoaderOptions;


public class LxExecutable extends yetmorecode.file.format.lx.LxExecutable {
    private FactoryBundledWithBinaryReader reader;
    DOSHeader mzHeader;
    
    public ArrayList<ObjectTableEntry> objects = new ArrayList<>();
    public int[] fixupPageTable;
    public HashMap<Integer, ArrayList<FixupRecord>> fixups = new HashMap<>();
    public int fixupCount;
    
	public LxExecutable(GenericFactory factory, ByteProvider bp, LoaderOptions options) throws IOException, InvalidHeaderException {
    	reader = new FactoryBundledWithBinaryReader(factory, bp, true);
    	// Try reading MZ header
        mzHeader = DOSHeader.createDOSHeader(reader);

        if (mzHeader.isDosSignature()) {
        	// Try reading LX header
        	header = new LxHeader(reader, (short) mzHeader.e_lfanew());
        	
        	// Read object table
        	int objectTableOffset = mzHeader.e_lfanew() + header.objectTableOffset;
        	for (int i = 0; i < header.objectCount; i++) {
        		var offset = objectTableOffset + i * yetmorecode.file.format.lx.ObjectTableEntry.SIZE;
        		ObjectTableEntry e = new ObjectTableEntry(reader, offset);
        		e.number = i+1;
        		objects.add(e);
        	}
        	
        	// Read fixup page table
        	fixupPageTable = new int[header.pageCount+1];
        	var tableOffset = getDosHeader().e_lfanew() + header.fixupPageTableOffset;
        	for (int i = 0; i <= header.pageCount; i++) {
        		fixupPageTable[i] = getReader().readInt(tableOffset + i * 4);
        	}
        	
        	// Read fixups
        	var fixupRecordOffset = getDosHeader().e_lfanew() + header.fixupRecordTableOffset;
        	fixupCount = 0;
        	//for (int i = 1; i <= header.pageCount; i++) {
        	for (var object : objects) {
        		for (var i = 0; i < object.pageCount; i++) {
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
    }
	
	public static void checkProvider(GenericFactory factory, ByteProvider provider) throws InvalidHeaderException, IOException {
		if (provider.length() < 4) {
			throw new InvalidHeaderException("File must have more than 4 bytes of content");
		}
		var reader = new FactoryBundledWithBinaryReader(factory, provider, true);
		
    	// Try parsing MZ header
        var mzHeader = DOSHeader.createDOSHeader(reader);
        if (!mzHeader.isDosSignature()) {
        	throw new InvalidHeaderException("No MS-DOS header found (invalid signature)"); 
        }
        
        // Try parsing LX Header
    	new LxHeader(reader, (short) mzHeader.e_lfanew());
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

	public DOSHeader getDosHeader() {
		return mzHeader;
	}
	
	public LxHeader getLeHeader() {
		return (LxHeader) header;
	}
	
	public ArrayList<ObjectTableEntry> getObjects() {
		return objects;
	}
	
	public int getFixupBegin(int page) {
		return fixupPageTable[page-1];
	}
	
	public int getFixupEnd(int page) {
		return fixupPageTable[page];
	}
	
	public int totalFixups() {
		int total = 0;
		for (var i = 1; i <= header.pageCount; i++) {
			total += fixups.get(i).size();
		}
		return total;
	}
	
	public boolean objectHasFixups(ObjectTableEntry object) {
		var total = 0;
		for (int i = 0; i < object.pageCount; i++) {
			var page = object.pageTableIndex + i;
			total += getFixupEnd(page) - getFixupBegin(page);
		}
		return total > 0;
	}
}

