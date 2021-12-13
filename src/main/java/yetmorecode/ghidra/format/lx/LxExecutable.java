package yetmorecode.ghidra.format.lx;

import java.io.IOException;
import java.util.ArrayList;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.mz.DOSHeader;
import yetmorecode.ghidra.format.lx.exception.InvalidHeaderException;


public class LxExecutable extends yetmorecode.file.format.lx.LxExecutable {
    private FactoryBundledWithBinaryReader reader;
    DOSHeader mzHeader;
    
    public ArrayList<ObjectTableEntry> objects = new ArrayList<>();
    public int[] fixupPageTable;
    
	public LxExecutable(GenericFactory factory, ByteProvider bp) throws IOException, InvalidHeaderException {
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
	
	public boolean objectHasFixups(ObjectTableEntry object) {
		var total = 0;
		for (int i = 0; i < object.pageCount; i++) {
			var page = object.pageTableIndex + i;
			total += getFixupEnd(page) - getFixupBegin(page);
		}
		return total > 0;
	}
}

