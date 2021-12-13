package yetmorecode.ghidra.format.lx.datatype;

import ghidra.program.model.data.EnumDataType;

public class LxOSType extends EnumDataType {

	public LxOSType() {
		super("os_type", 2);
		add("unknown", 0);
		add("OS/2", 1);
		add("win1", 2);
		add("dos4", 3);
		add("win3", 4);
		add("IBM", 5);
	}

}
