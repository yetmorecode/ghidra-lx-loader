package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import yetmorecode.file.format.vxd.VersionResource;
import yetmorecode.file.format.vxd.fileinfo.VS_VarFileInfo;

public class VxDVersionResource extends VersionResource implements StructConverter {
	public final static String DATATYPE_NAME = "IMAGE_VXD_VERSION_RESOURCE";
	private StructureDataType dt = new StructureDataType(DATATYPE_NAME, 0);
	
	private StructureDataType vartype = new StructureDataType("VarFileInfo", 0);
	private StructureDataType versiontype = new StructureDataType("VS_VERSIONINFO", 0);
	private StructureDataType infotype = new StructureDataType("VS_FIXEDFILEINFO", 0);
	private FactoryBundledWithBinaryReader reader;
	
	public VxDVersionResource(FactoryBundledWithBinaryReader reader, long index) throws IOException {
		this.reader = reader;
		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(index);
		cType = nextByte("cType", "");
		wID = nextShort(dt, "wID", "Resource ID");
		cName = nextByte("cName", "");
		wOrdinal = nextShort(dt, "wOrdinal", "Ordinal of following resource");
		wFlags = nextShort(dt, "wFlags", "");
		dwResSize = nextInt(dt, "dwResSize", "Size of following resource");
		
		
		info.wLength = nextShort(versiontype, "wLength", "The length, in bytes, of the VS_VERSIONINFO structure. This length does not include any padding that aligns any subsequent version resource data on a 32-bit boundary.");
		info.wType = nextShort(versiontype, "wType", "");
		info.szKey = reader.readNextAsciiString();
		versiontype.add(new ArrayDataType(StructConverter.ASCII, info.szKey.length()+1, 1), "szKey", "VS_VERSION_INFO");
		
		info.value.dwSignature = nextInt(infotype, "dwSignature", "Contains the value 0xFEEF04BD. See verrsrc.h (include Windows.h). This is used with the szKey member of the VS_VERSIONINFO structure when searching a file for the VS_FIXEDFILEINFO structure.");
		info.value.dwStrucVersion = nextInt(infotype, "dwStrucVersion", "The binary version number of this structure. The high-order word of this member contains the major version number, and the low-order word contains the minor version number.");
		info.value.dwFileVersionMS = nextInt(infotype, "dwFileVersionMS", "The most significant 32 bits of the file's binary version number. This member is used with dwFileVersionLS to form a 64-bit value used for numeric comparisons.");
		info.value.dwFileVersionLS = nextInt(infotype, "dwFileVersionLS", "The least significant 32 bits of the file's binary version number. This member is used with dwFileVersionMS to form a 64-bit value used for numeric comparisons.");
		info.value.dwProductVersionMS = nextInt(infotype, "dwProductVersionMS", "The most significant 32 bits of the binary version number of the product with which this file was distributed. This member is used with dwProductVersionLS to form a 64-bit value used for numeric comparisons.");
		info.value.dwProductVersionLS = nextInt(infotype, "dwProductVersionLS", "The least significant 32 bits of the binary version number of the product with which this file was distributed. This member is used with dwProductVersionMS to form a 64-bit value used for numeric comparisons.");
		info.value.dwFileFlagsMask = nextInt(infotype, "dwFileFlagsMask", "Contains a bitmask that specifies the valid bits in dwFileFlags. A bit is valid only if it was defined when the file was created.");
		// TODO: Add types
		info.value.dwFileFlags = nextInt(infotype, "dwFileFlags", "Contains a bitmask that specifies the Boolean attributes of the file.");
		info.value.dwFileOS = nextInt(infotype, "dwFileOS", "The operating system for which this file was designed.");
		info.value.dwFileType = nextInt(infotype, "dwFileType", "The general type of file.");
		info.value.dwFileSubtype = nextInt(infotype, "dwFileSubtype", "The function of the file. The possible values depend on the value of dwFileType. For all values of dwFileType not described in the following list, dwFileSubtype is zero.");
		info.value.dwFileDateMS = nextInt(infotype, "dwFileDateMS", "The most significant 32 bits of the file's 64-bit binary creation date and time stamp.");
		info.value.dwFileDateLS = nextInt(infotype, "dwFileDateLS", "The least significant 32 bits of the file's 64-bit binary creation date and time stamp.");
		versiontype.add(infotype, "Value", "VS_FIXEDFILEINFO");

		
		var len = reader.readNextShort();
		var type = reader.readNextShort();
		var key = reader.readNextAsciiString();
		if (key.equals("VarFileInfo")) {
			var v = new VS_VarFileInfo();	
			v.wLength = len;
			v.wType = type;
			v.szKey = key;
			vartype.add(StructConverter.WORD, 2, "wLength", "The length, in bytes, of the entire VarFileInfo block, including all structures indicated by the Children member.");
			vartype.add(StructConverter.WORD, 2, "wType", "");
			vartype.add(new ArrayDataType(StructConverter.ASCII, v.szKey.length()+1, 1), "szKey", "");
			if (reader.getPointerIndex() % 4 != 0) {
				v.Padding = nextShort(vartype, "Padding", "");	
			}
			v.varLength = nextShort(vartype, "transLength", "The length, in bytes, of the VS_VERSIONINFO structure. This length does not include any padding that aligns any subsequent version resource data on a 32-bit boundary.");
			v.varszKey = reader.readNextAsciiString();
			vartype.add(new ArrayDataType(StructConverter.ASCII, v.varszKey.length()+1, 1), "transKey", "TRANSLATION");
			vartype.add(new ArrayDataType(StructConverter.DWORD, v.varLength / 4, 4), "Children", "An array of one or more values that are language and code page identifier pairs.");
			
			versiontype.add(vartype);
		}
		
		dt.add(versiontype, "Children", "VS_VERSIONINFO");
		
		
		reader.setPointerIndex(oldIndex);
	}
	
	private byte nextByte(String name, String comment) throws IOException {
		dt.add(BYTE, 1, name, comment);
		return reader.readNextByte();
	}
	
	private short nextShort(StructureDataType d, String name, String comment) throws IOException {
		d.add(WORD, 2, name, comment);
		return reader.readNextShort();
	}
	
	private int nextInt(StructureDataType d, String name, String comment) throws IOException {
		d.add(DWORD, 4, name, comment);
		return reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return dt;
	}
}
