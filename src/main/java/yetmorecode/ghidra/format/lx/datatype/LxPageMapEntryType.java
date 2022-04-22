package yetmorecode.ghidra.format.lx.datatype;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.StructureDataType;

public class LxPageMapEntryType extends StructureDataType {

	public LxPageMapEntryType() {
		super("page_entry", 0);
		add(StructConverter.DWORD, "offset", "Data offset in file");
		add(StructConverter.WORD, "size", "Data size in file");
		add(StructConverter.WORD, "flags", "Page flags");
	}

}
