package yetmorecode.ghidra.format.lx.datatype;

import ghidra.program.model.data.EnumDataType;

public class LxByteOrder extends EnumDataType {
	public LxByteOrder() {
		super("byte_order", 1);
		add("LE", 0);
		add("BE", 1);
	}
}
