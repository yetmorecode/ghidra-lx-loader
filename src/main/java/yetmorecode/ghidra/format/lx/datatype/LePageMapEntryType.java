package yetmorecode.ghidra.format.lx.datatype;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.StructureDataType;

public class LePageMapEntryType extends StructureDataType {

	public LePageMapEntryType() {
		super("page_entry", 0);
		add(
			new ArrayDataType(StructConverter.BYTE, 3, 0), 
			"index", 
			"Page index into data pages"
		);
		add(StructConverter.BYTE, "flags", "Page flags");
	}

}
