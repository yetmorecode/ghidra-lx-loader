package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import yetmorecode.file.format.vxd.DescriptionBlock;

public class VxDDescriptionBlock extends DescriptionBlock implements StructConverter {
	public final static String DATATYPE_NAME = "IMAGE_VXD_DESCRIPTION";
	
	private StructureDataType dt = new StructureDataType(DATATYPE_NAME, 0);
	
	private FactoryBundledWithBinaryReader reader;
	
	public VxDDescriptionBlock(FactoryBundledWithBinaryReader reader, long index) throws IOException {
		this.reader = reader;
		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(index);
		DDB_Next = nextInt("DDB_Next", "VMM RESERVED FIELD");
		DDB_SDK_Version = nextShort("DDB_SDK_Version", "INIT <DDK_VERSION> RESERVED FIELD");
		DDB_Req_Device_Number = nextShort("DDB_Req_Device_Number", "INIT <UNDEFINED_DEVICE_ID>");
		DDB_Dev_Major_Version = nextByte("DDB_Dev_Major_Version", "INIT <0> Major device number");
		DDB_Dev_Minor_Version = nextByte("DDB_Dev_Minor_Version", "INIT <0> Minor device number");
		DDB_Flags = nextShort("DDB_Flags", "INIT <0> for init calls complete");
		dt.add(new ArrayDataType(ASCII,8,1), "DDB_Name", "AINIT <\"        \"> Device name");
		DDB_Init_Order = nextInt("DDB_Init_Order", "INIT <UNDEFINED_INIT_ORDER>");
		DDB_Control_Proc = nextInt("DDB_Control_Proc", "Offset of control procedure");
		DDB_V86_API_Proc = nextInt("DDB_V86_API_Proc", "INIT <0> Offset of API procedure");
		DDB_PM_API_Proc = nextInt("DDB_PM_API_Proc", "INIT <0> Offset of API procedure");
		DDB_V86_API_CSIP = nextInt("DDB_V86_API_CSIP", "INIT <0> CS:IP of API entry point");
		DDB_PM_API_CSIP = nextInt("DDB_PM_API_CSIP", "INIT <0> CS:IP of API entry point");
		DDB_Reference_Data = nextInt("DDB_Reference_Data", "Reference data from real mode");
		DDB_Service_Table_Ptr = nextInt("DDB_Service_Table_Ptr", "INIT <0> Pointer to service table");
		DDB_Service_Table_Size = nextInt("DDB_Service_Table_Size", "INIT <0> Number of services");
		DDB_Win32_Service_Table = nextInt("DDB_Win32_Service_Table", "INIT <0> Pointer to Win32 services");
		DDB_Prev = nextInt("DDB_Prev", "INIT <'Prev'> Ptr to prev 4.0 DDB");
		DDB_Reserved0 = nextInt("DDB_Reserved0", "INIT <0> Reserved");
		DDB_Reserved1 = nextInt("DDB_Reserved1", "INIT <'Rsv1'> Reserved");
		DDB_Reserved2 = nextInt("DDB_Reserved2", "INIT <'Rsv2'> Reserved");
		DDB_Reserved3 = nextInt("DDB_Reserved3", "INIT <'Rsv3'> Reserved");
		reader.setPointerIndex(oldIndex);
	}
	
	private byte nextByte(String name, String comment) throws IOException {
		dt.add(BYTE, 1, name, comment);
		return reader.readNextByte();
	}
	
	private short nextShort(String name, String comment) throws IOException {
		dt.add(WORD, 2, name, comment);
		return reader.readNextShort();
	}
	
	private int nextInt(String name, String comment) throws IOException {
		dt.add(DWORD, 4, name, comment);
		return reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return dt;
	}
}
