package yetmorecode.ghidra.format.lx.datatype;

import ghidra.program.model.data.EnumDataType;

public class LxByteOrder extends EnumDataType {
	public LxByteOrder() {
		super("order", 1);
		add("little", 0);
		add("big", 1);
	}
}
