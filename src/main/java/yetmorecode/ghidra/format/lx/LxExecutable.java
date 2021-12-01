package yetmorecode.ghidra.format.lx;

import java.io.IOException;
import java.util.ArrayList;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.mz.DOSHeader;
import yetmorecode.file.format.lx.ObjectTableEntry;
import yetmorecode.ghidra.format.lx.exception.InvalidHeaderException;


public class LxExecutable extends yetmorecode.file.format.lx.LxExecutable {
    private FactoryBundledWithBinaryReader reader;
    DOSHeader mzHeader;
    
    public ArrayList<ObjectMapEntry> objects = new ArrayList<>();
    
	public LxExecutable(GenericFactory factory, ByteProvider bp) throws IOException, InvalidHeaderException {
    	reader = new FactoryBundledWithBinaryReader(factory, bp, true);
        mzHeader = DOSHeader.createDOSHeader(reader);

        if (mzHeader.isDosSignature()) {
        	header = new LxHeader(reader, (short) mzHeader.e_lfanew());
        	
        	//objectTable = new ArrayList<ObjectMapEntry>(header.objectCount);
        	int objectTableOffset = mzHeader.e_lfanew() + header.objectTableOffset;
        	for (int i = 0; i < header.objectCount; i++) {
        		ObjectMapEntry e = new ObjectMapEntry(reader, objectTableOffset + i * ObjectTableEntry.SIZE);
        		e.number = i+1;
        		//objectTable.add(e);
        		objects.add(e);
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

	public ArrayList<ObjectMapEntry> getObjects() {
		return objects;
	}
}

