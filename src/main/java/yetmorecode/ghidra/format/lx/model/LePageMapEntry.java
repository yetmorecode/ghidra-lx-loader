package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;
import ghidra.util.BigEndianDataConverter;
import yetmorecode.file.format.lx.LePageTableEntry;

public class LePageMapEntry extends LePageTableEntry {
	public LePageMapEntry(Executable exe, int page) throws IOException {
		var reader = exe.getBinaryReader();
		var oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(exe.lfanew + exe.header.pageTableOffset + page * SIZE);
		long data = BigEndianDataConverter.INSTANCE.getInt(reader.readNextByteArray(4));
		dataOffset = (int) ((data & 0xffffff00) >> 8);		
		flags = (byte)(data & 0xff);
		if (index == exe.header.pageCount) {
			dataSize = (short) exe.header.lastPageSize;
		} else {
			dataSize = (short) exe.header.pageSize;
		}
		reader.setPointerIndex(oldIndex);
	}
}
