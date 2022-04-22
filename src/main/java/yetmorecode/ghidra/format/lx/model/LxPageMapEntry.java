package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;
import yetmorecode.file.format.lx.LxPageTableEntry;

public class LxPageMapEntry extends LxPageTableEntry {
	public LxPageMapEntry(Executable exe, int page) throws IOException {
		var reader = exe.getBinaryReader();
		var oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(exe.lfanew + exe.header.pageTableOffset + page * SIZE);
		dataOffset = reader.readNextInt();
		dataSize = reader.readNextShort();
		flags = reader.readNextShort();
		reader.setPointerIndex(oldIndex);
	}
}
