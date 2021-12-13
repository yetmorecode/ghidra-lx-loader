package yetmorecode.ghidra.format.lx;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Conv;
import ghidra.util.exception.DuplicateNameException;
import yetmorecode.ghidra.format.lx.datatype.LxByteOrder;
import yetmorecode.ghidra.format.lx.datatype.LxCpuType;
import yetmorecode.ghidra.format.lx.datatype.LxOSType;
import yetmorecode.ghidra.format.lx.exception.InvalidHeaderException;

public class LxHeader extends yetmorecode.file.format.lx.LxHeader implements StructConverter {
	
	public final static String DATATYPE_NAME = "IMAGE_LE_HEADER";
	
	private StructureDataType dt = new StructureDataType(DATATYPE_NAME, 0);
	
	public int unknown;
	
	public LxHeader(FactoryBundledWithBinaryReader reader, short index) throws IOException, InvalidHeaderException {
		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(Conv.shortToInt(index));

		signature = reader.readNextShort();
		if (signature != SIGNATURE_LE &&
			signature != SIGNATURE_LX &&
			signature != SIGNATURE_LC
		) {
			throw new InvalidHeaderException();
		}
		dt.add(
			new ArrayDataType(ASCII,2,1), 
			"signature", 
			"Magic number for LX/LE/LC"
		);
		byteOrdering = reader.readNextByte();
		dt.add(
			new LxByteOrder(), 1, "byteOrdering", 
			"Byte ordering for EXE"
		);
		wordOrdering = reader.readNextByte();
		dt.add(
			new LxByteOrder(), 1, "wordOrdering", 
			"Word ordering for EXE"
		);
		formatLevel = reader.readNextInt();
		dt.add(
			DWORD, 4, "formatLevel", 
			"EXE Format Level is set to 0 for the initial version of the 32-bit linear EXE format. Each incompatible change to the linear EXE format must increment thisvalue. This allows the system to recognized future EXE file versions so that anappropriate error message may be displayed if an attempt is made to load them."
		);
		cpuType = reader.readNextShort();
		dt.add(new LxCpuType(), 2, "cpuType", "CPU");
		osType = reader.readNextShort();
		dt.add(new LxOSType(), 2, "osType", "OS");
		
		moduleVersion = reader.readNextInt();
		dt.add(
			DWORD, 4, "moduleVersion", 
			"Version of the linear EXE module. Useful for differentiating between revisions of dynamic linked modules. Specified at link time by the user."
		);
		moduleFlags = reader.readNextInt();
		dt.add(
			DWORD, 4, "moduleFlags", 
			"Flag bits for the module."
		);
		pageCount = reader.readNextInt();
		dt.add(
			DWORD, 4, "pageCount", 
			"# of physical pages in module. This field specifies the number of pages physically contained in this module. In other words, pages containing either enumerated or iterated data, not invalid or zero-fillpages. These pages are contained in the ‘preload pages’, ‘demand load pages’ and ‘iterated data pages’ sections of the linear EXE module."
		);	
		eipObject = reader.readNextInt();
		dt.add(
			DWORD, 4, "eipObject", 
			"Object # to which the Entry Address is relative."
		);	
		eip = reader.readNextInt();
		dt.add(
			DWORD, 4, "eip", 
			"Entry Address of module. The Entry Address is the starting address for program modules and the library initialization and Library termination address for library modules."
		);
		espObject = reader.readNextInt();
		dt.add(
			DWORD, 4, "espObject", 
			"The Object number to which the ESP is relative.This specifies the object to which the starting ESP is relative. This must be anonzero value for a program module to be correctly loaded. This field is ignored for alibrary module."
		);
		esp = reader.readNextInt();
		dt.add(
			DWORD, 4, "esp", 
			"Starting stack address of module."
		);
		pageSize = reader.readNextInt();
		dt.add(
			DWORD, 4, "pageSize", 
			"The size of one page for this system."
		);
		lastPageSize = reader.readNextInt();
		dt.add(
			DWORD, 4, "lastPageSize", 
			"Bytes on last page (only LE) / Page offset shift (LX)"
		);
		fixupSectionSize = reader.readNextInt();
		dt.add(
			DWORD, 4, "fixupSectionSize", 
			"Total size of the fixup information in bytes. This includes the following 4 tables:Fixup Page TableFixup Record TableImport Module name TableImport Procedure Name Table"
		);
		fixupSectionChecksum = reader.readNextInt();
		dt.add(
			DWORD, 4, "fixupSectionChecksum", 
			"Checksum for fixup information. If the checksum feature is not implemented, then the linker will set these fields to zero."
		);
		loaderSectionSize = reader.readNextInt();
		dt.add(
			DWORD, 4, "loaderSectionSize", 
			"Flag bits for the module."
		);
		loaderSectionChecksum = reader.readNextInt();
		dt.add(
			DWORD, 4, "loaderSectionChecksum", 
			"Checksum for loader section. If the checksum feature is not implemented, then the linker will set these fields to zero."
		);
		objectTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "objectTableOffset", 
			"Object Table offset. This offset is relative to the beginning of the linear EXE header. This offset alsopoints to the start of the Loader Section."
		);
		objectCount = reader.readNextInt();
		dt.add(
			DWORD, 4, "objectCount", 
			"# of entries in Object Table."
		);
		pageTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "pageTableOffset", 
			"Object Page Table offset. This offset is relative to the beginning of the linear EXE header."
		);
		iterPagesOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "iterPagesOffset", 
			"Object Iterated Pages offset. This offset is relative to the beginning of the EXE file."
		);
		resourceTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "resourceTableOffset", 
			"Resource Table offset. This offset is relative to the beginning of the linear EXE header."
		);
		resourceCount = reader.readNextInt();
		dt.add(
			DWORD, 4, "resourceCount", 
			"# of entries in Resource Table."
		);
		residentNameTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "residentNameTableOffset", 
			"Resident Name Table offset. This offset is relative to the beginning of the linear EXE header."
		);
		entryTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "entryTableOffset", 
			"Entry Table offset. This offset is relative to the beginning of the linear EXE header."
		);
		directivesTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "directivesTableOffset", 
			"Module Format Directives Table offset.This offset is relative to the beginning of the linear EXE header."
		);
		directivesCount = reader.readNextInt();
		dt.add(
			DWORD, 4, "directivesCount", 
			"# of Module Format Directives in the Table.This field specifies the number of entries in the Module Format Directives Table. "
		);
		fixupPageTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "fixupPageTableOffset", 
			"Fixup Page Table offset. This offset is relative to the beginning of the linear EXE header. This offset alsopoints to the start of the Fixup Section."
		);
		fixupRecordTableOffset =  reader.readNextInt();
		dt.add(
			DWORD, 4, "fixupRecordTableOffset", 
			"Fixup Record Table Offset. This offset is relative to the beginning of the linear EXE header"
		);
		importModuleNameTableOffset =  reader.readNextInt();
		dt.add(
			DWORD, 4, "importModuleNameTableOffset", 
			"Import Module Name Table offset.This offset is relative to the beginning of the linear EXE header."
		);
		importModuleNameCount =  reader.readNextInt();
		dt.add(
			DWORD, 4, "importModuleNameCount", 
			"# of entries in the Import Module Name Table"
		);
		importProcedureNameTableOffset =  reader.readNextInt();
		dt.add(
			DWORD, 4, "importProcedureNameTableOffset", 
			"Import Procedure Name Table offset. This offset is relative to the beginning of the linear EXE header."
		);
		checksumTableOffset =  reader.readNextInt();
		dt.add(
			DWORD, 4, "checksumTableOffset", 
			"Per-Page Checksum Table offset.This offset is relative to the beginning of the linear EXE header."
		);
		dataPagesOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "dataPagesOffset", 
			"Data Pages Offset. This offset is relative to the beginning of the EXE file. This offset also points to thestart of the Data Section."
		);
		preloadPagesCount =  reader.readNextInt();
		dt.add(
			DWORD, 4, "preloadPagesCount", 
			"# of Preload pages for this module.Note: OS/2 2.0 does not respect the preload of pages as specified in theexecutable file for performance reasons."
		);
		nameTableOffset =  reader.readNextInt();
		dt.add(
			DWORD, 4, "nameTableOffset", 
			"Non-Resident Name Table offset. This offset is relative to the beginning of the EXE file"
		);
		nameTableLength =  reader.readNextInt();
		dt.add(
			DWORD, 4, "nameTableLength", 
			"# of bytes in the Non-resident name table"
		);
		nameTableChecksum =  reader.readNextInt();
		dt.add(
			DWORD, 4, "nameTableChecksum", 
			"Non-Resident Name Table Checksum"
		);
		autoDataSegmentObjectNumber =  reader.readNextInt();
		dt.add(
			DWORD, 4, "autoDataSegmentObjectNumber", 
			"Auto Data Segment Object number.This is the object number for the Auto Data Segment used by 16-bit modules. Thisfield is supported for 16-bit compatibility only and is not used by 32-bit modules."
		);
		debugOffset =  reader.readNextInt();
		dt.add(
			DWORD, 4, "debugOffset", 
			"Debug Information offset. This offset is relative to the beginning of the file. This offset also points to the start of theDebug Section."
		);
		debugLength =  reader.readNextInt();
		dt.add(
			DWORD, 4, "debugLength", 
			"Debug Information length"
		);
		pagesInPreloadSectionCount =  reader.readNextInt();
		dt.add(
			DWORD, 4, "pagesInPreloadSectionCount", 
			"# of instance data pages found in the preload section."
		);
		pagesInDemandSectionCount =  reader.readNextInt();
		dt.add(
			DWORD, 4, "pagesInDemandSectionCount", 
			"# of instance data pages found in the demand section."
		);
		heapSize =  reader.readNextInt();
		dt.add(
			DWORD, 4, "heapSize", 
			"Heap size added to the Auto DS Object"
		);
		stackSize =  reader.readNextInt();
		dt.add(
			DWORD, 4, "stackSize", 
			"Stack size"
		);
		dt.add(new ArrayDataType(BYTE, 0x14, 0), "e32_res3", "Pad structure to 196 bytes");
		reader.setPointerIndex(oldIndex);
	}
	
	public String getTypePrefix() {
		if (signature == SIGNATURE_LX) {
			return "lx";
		}
		if (signature == SIGNATURE_LC) {
			return "lc";
		}
		return "le";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return dt;
	}
}
