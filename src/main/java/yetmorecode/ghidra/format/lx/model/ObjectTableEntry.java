package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;
import java.util.ArrayList;

import yetmorecode.file.format.lx.LinearObjectTableEntry;

public class ObjectTableEntry extends LinearObjectTableEntry {
	public long offset;
	
	public ObjectTableEntry(Executable exe, int number) throws IOException {
		var reader = exe.getBinaryReader();
		var oldIndex = reader.getPointerIndex();
		var objectTableOffset = exe.lfanew + exe.header.objectTableOffset;
		this.offset = objectTableOffset + number * SIZE;
		this.number = number + 1;
		reader.setPointerIndex(offset);
		size = reader.readNextInt();		
		base = reader.readNextInt();
		flags = reader.readNextInt();
		pageTableIndex = reader.readNextInt();
		pageCount = reader.readNextInt();
		reserved = reader.readNextInt();
		reader.setPointerIndex(oldIndex);
	}
	
	public String getPermissionFlagsLabel() {
		return String.format(
			"%s%s%s",
			(flags & FLAG_READABLE) > 0 ? "r" : "-",
			(flags & FLAG_WRITEABLE) > 0 ? "w" : "-",
			(flags & FLAG_EXECUTABLE) > 0 ? "x" : "-"			
		);
	}
	
	public String getExtraFlagsLabel() {
		ArrayList<String> f = new ArrayList<>();
		f.add(getPermissionFlagsLabel());
		if ((flags & FLAG_PRELOAD_PAGES) > 0) {
			f.add("preload pages");
		}
		if ((flags & FLAG_1616_ALIAS) > 0) {
			f.add("16:16 alias");
		}
		if ((flags & FLAG_BIG_DEFAULT_BIT) > 0) {
			f.add("big default");
		}
		return String.format("%04x (%s)", flags, String.join(", ", f));
	}
}