package yetmorecode.ghidra.format.lx.datatype;

import ghidra.program.model.data.EnumDataType;

public class FixupTargetFlags extends EnumDataType {
	public FixupTargetFlags() {
		super("flags", 1);
		add("INTERNAL", 0);
		add("EXTERN_ORDINAL", 1);
		add("EXTERN_NAME", 2);
		add("EXTERN_ENTRY", 3);
		add("ADDITIVE", 4);
		add("CHAINING", 8);
		add("OFFSET_32", 0x10);
		add("ADDITIVE_32", 0x20);
		add("OBJECT_16", 0x40);
		add("ORDINAL_8", 0x80);
	}
}
