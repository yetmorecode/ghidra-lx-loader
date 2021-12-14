package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import yetmorecode.file.format.lx.LxFixupRecord;
import yetmorecode.ghidra.format.lx.datatype.FixupSourceType;
import yetmorecode.ghidra.format.lx.datatype.FixupTargetFlags;

public class FixupRecord extends LxFixupRecord implements StructConverter {

	public int sourceCount = 1;
	public int index;
	public int size;
	public int pageAddress;
	
	public static String[] shortnames = {
		"byte",
		"inv1",
		"sel16",
		"p1616",
		"inv4",
		"off16",
		"p1632",
		"off32",
		"off32s",
	};
	
	private StructureDataType dt;
	
	public FixupRecord(FactoryBundledWithBinaryReader reader, int offset, int number, int baseAddress, int page) throws IOException {
		var oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(offset);
		index = number;
		this.pageAddress = baseAddress + page * 0x1000;
		
		sourceType = reader.readNextByte();
		targetFlags = reader.readNextByte();
		size = 2;
		// source data
		if (hasSourceList()) {
			sourceCount = reader.readNextByte();
			size++;
		} else {
			ByteBuffer bb = ByteBuffer.allocate(2);
			bb.order(ByteOrder.LITTLE_ENDIAN);
			bb.put(reader.readNextByte());
			bb.put(reader.readNextByte());
			sourceOffset = bb.getShort(0);
			size += 2;
		}
		
		dt = new StructureDataType(String.format("%08x", getSourceAddress()), 0);
		dt.add(new FixupSourceType(), "sourceType", "The source type specifies the size and type of the fixup to be performed on the fixup source.");
		dt.add(new FixupTargetFlags(), "targetFlags", "The target flags specify how the target information is interpreted.");
		if (hasSourceList()) {
			dt.add(BYTE, "sourceCount", "");
		} else {
			dt.add(WORD, "sourceOffset", 
					"This field contains either an offset or a count depending on the Source List Flag. Ifthe Source List Flag is set, a list of source offsets follows the additive field and thisfield contains the count of the entries in the source offset list. Otherwise, this is thesingle source offset for the fixup. Source offsets are relative to the beginning of thepage where the fixup is to be made.\r\n"
					+ "Note: For fixups that cross page boundaries, a separate fixup record is specifiedfor each page. An offset is still used for the 2nd page but it now becomes anegative offset since the fixup originated on the preceding page. (Forexample, if only the last one byte of a 32-bit address is on the page to befixed up, then the offset would have a value of -3.)"
			);
		}
		
		// target data
		if (objectNumber16Bit()) {
			objectNumber = reader.readNextShort();
			dt.add(WORD, "objectNumber", "This field is an index into the current module’s Object Table to specify the targetObject. It is a Byte value when the ‘16-bit Object Number/Module Ordinal Flag’ bit inthe target flags field is clear and a Word value when the bit is set.");
			size += 2;
		} else {
			objectNumber = reader.readNextByte();
			if (objectNumber < 0) {
				objectNumber += 0x100;
			}
			dt.add(BYTE, "objectNumber", "This field is an index into the current module’s Object Table to specify the targetObject. It is a Byte value when the ‘16-bit Object Number/Module Ordinal Flag’ bit inthe target flags field is clear and a Word value when the bit is set.");
			size++;
		}
		
		if (isInternalTarget()) {
			if (getSourceType() == SOURCE_16BIT_SELECTOR_FIXUP) {
				// no target offset
			} else if (isTargetOffset32Bit()) {
				targetOffset = reader.readNextInt();
				dt.add(DWORD, "targetOffset", "This field is an offset into the specified target Object. It is not present when theSource Type specifies a 16-bit Selector fixup. It is a Word value when the ‘32-bitTarget Offset Flag’ bit in the target flags field is clear and a Dword value when the bitis set.");
				size += 4;
			} else {
				targetOffset = reader.readNextShort();
				dt.add(WORD, "targetOffset", "This field is an offset into the specified target Object. It is not present when theSource Type specifies a 16-bit Selector fixup. It is a Word value when the ‘32-bitTarget Offset Flag’ bit in the target flags field is clear and a Dword value when the bitis set.");
				size += 2;
				if (targetOffset < 0) {
					targetOffset += 0x10000;
				}
			}
		} else {
			Msg.warn(this, String.format("External fixup. Unhandled.."));
		}
		
		if (hasSourceList()) {
			for (int i = 0; i < sourceCount; i++) {
				sourceList.add(reader.readNextShort());
			}
			dt.add(new ArrayDataType(WORD, sourceCount, 0), "source_list", "");
		}
		
		reader.setPointerIndex(oldIndex);
	}
	
	public int getSourceAddress() {
		return pageAddress + sourceOffset;
	}
	
	public boolean hasSourceList() {
		return (sourceType & SOURCE_SOURCE_LIST) > 0;
	}
	
	public boolean objectNumber16Bit() {
		return (targetFlags & 0x40) > 0;
	}
	
	public boolean isInternalTarget() {
		return (targetFlags & 0x3) == 0;
	}
	
	public int getSourceType() {
		return sourceType & SOURCE_MASK;
	}
	
	public boolean isTargetOffset32Bit() {
		return (targetFlags & 0x10) > 0;
	}
	
	public boolean is1616PointerFixup() {
		return getSourceType() == SOURCE_1616PTR_FIXUP;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return dt;
	}
	
	public String shortname() {
		return shortnames[getSourceType()];
	}
}
