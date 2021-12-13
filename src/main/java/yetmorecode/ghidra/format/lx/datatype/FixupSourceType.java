package yetmorecode.ghidra.format.lx.datatype;

import ghidra.program.model.data.EnumDataType;

public class FixupSourceType extends EnumDataType {

	public FixupSourceType() {
		super("src_type", 1);
		add("FIX_BYTE", 0);
		add("INVALID1", 1);
		add("FIX_PTR1616 ", 2);
		add("FIX_SEGMENT_16", 3);
		add("INVALID4", 4);
		add("FIX_OFFSET16", 5);
		add("FIX_PTR1632", 6);
		add("FIX_OFFSET32", 7);
		add("FIX_OFFSET32_SELF", 7);
		add("TO_ALIAS", 0x10);
		add("SOURCELIST", 0x20);
	}
}
