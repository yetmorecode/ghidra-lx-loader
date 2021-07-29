package yetmorecode.ghidra.format.lx;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import yetmorecode.file.format.lx.ObjectTableEntry;

public class ObjectMapEntry extends ObjectTableEntry {

	public ObjectMapEntry(FactoryBundledWithBinaryReader reader, int index) throws IOException {
		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(index);
		size = reader.readNextInt();
		base = reader.readNextInt();
		flags = reader.readNextInt();
		pageTableIndex = reader.readNextInt();
		pageCount = reader.readNextInt();
		reader.setPointerIndex(oldIndex);
	}
}