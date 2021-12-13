package yetmorecode.ghidra.format.lx.datatype;

import ghidra.program.model.data.EnumDataType;

public class LxCpuType extends EnumDataType {

	public LxCpuType() {
		super("cpu_type", 2);
		add("x86", 0);
		add("286+", 1);
		add("386+", 2);
		add("486+", 3);
	}

}
