package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.util.BigEndianDataConverter;

public class PageMapEntry {
	private int index;
	private byte flags;
	
	public PageMapEntry(FactoryBundledWithBinaryReader reader, int index) throws IOException {
		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(index);

		long data = BigEndianDataConverter.INSTANCE.getInt(reader.readNextByteArray(4));
		this.index = (int) ((data & 0xffffff00) >> 8);		
		flags = (byte)(data & 0xff);
		
		reader.setPointerIndex(oldIndex);
	}

	public int getIndex() {
		return index;
	}
	
	public int getOffset() {
		return this.getIndex();
	}

	public byte getFlags() {
		return flags;
	}
	
}
