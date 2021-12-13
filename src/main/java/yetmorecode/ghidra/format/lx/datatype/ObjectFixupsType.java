package yetmorecode.ghidra.format.lx.datatype;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.StructureDataType;
import yetmorecode.ghidra.format.lx.LxExecutable;
import yetmorecode.ghidra.format.lx.ObjectTableEntry;

public class ObjectFixupsType extends StructureDataType {

	public ObjectFixupsType(LxExecutable executable, ObjectTableEntry object) {
		super("fixups" + object.number, 0);
		for (int i = 0; i < object.pageCount; i++) {
			var page = object.pageTableIndex + i;
			var size = executable.getFixupEnd(page) - executable.getFixupBegin(page);
			if (size > 0) {
				add(new ArrayDataType(StructConverter.BYTE, size, 0), String.format("fixup_%x", page), "Page #" + page + " fixups");
			}
		}
	}

}
