package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import yetmorecode.file.format.lx.LinearHeader;
import yetmorecode.ghidra.format.lx.datatype.LxByteOrder;
import yetmorecode.ghidra.format.lx.datatype.LxCpuType;
import yetmorecode.ghidra.format.lx.datatype.LxOSType;
import yetmorecode.ghidra.lx.InvalidHeaderException;

public class Header extends yetmorecode.file.format.lx.LinearHeader implements StructConverter {
	
	public final static String DATATYPE_NAME = "IMAGE_LE_HEADER";
	
	private StructureDataType dt = new StructureDataType(DATATYPE_NAME, 0);
	
	public int unknown;
	
	public Header(FactoryBundledWithBinaryReader reader, long index) throws IOException, InvalidHeaderException {
		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(index);

		signature = reader.readNextShort();
		if (!isLe() && !isLx() && !isLc()) {
			throw new InvalidHeaderException("Signature does not match LX/LE/LC");
		}
		dt.add(
			new ArrayDataType(ASCII,2,1), 
			"e32_magic", 
			"Magic number for LX/LE/LC"
		);
		byteOrdering = reader.readNextByte();
		dt.add(
			new LxByteOrder(), 1, "e32_border", 
			"Byte ordering for EXE"
		);
		wordOrdering = reader.readNextByte();
		dt.add(
			new LxByteOrder(), 1, "e32_worder", 
			"Word ordering for EXE"
		);
		formatLevel = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_level", 
			"EXE Format Level is set to 0 for the initial version of the 32-bit linear EXE format. Each incompatible change to the linear EXE format must increment thisvalue. This allows the system to recognized future EXE file versions so that anappropriate error message may be displayed if an attempt is made to load them."
		);
		cpuType = reader.readNextShort();
		dt.add(new LxCpuType(), 2, "e32_cpu", "CPU");
		osType = reader.readNextShort();
		dt.add(new LxOSType(), 2, "e32_os", "OS");
		
		moduleVersion = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_ver", 
			"Version of the linear EXE module. Useful for differentiating between revisions of dynamic linked modules. Specified at link time by the user."
		);
		moduleFlags = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_mflags", 
			"Flag bits for the module."
		);
		pageCount = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_mpages", 
			"# of physical pages in module. This field specifies the number of pages physically contained in this module. In other words, pages containing either enumerated or iterated data, not invalid or zero-fillpages. These pages are contained in the ‘preload pages’, ‘demand load pages’ and ‘iterated data pages’ sections of the linear EXE module."
		);	
		eipObject = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_startobj", 
			"Object # to which the Entry Address is relative."
		);	
		eip = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_eip", 
			"Entry Address of module. The Entry Address is the starting address for program modules and the library initialization and Library termination address for library modules."
		);
		espObject = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_stackobj", 
			"The Object number to which the ESP is relative.This specifies the object to which the starting ESP is relative. This must be anonzero value for a program module to be correctly loaded. This field is ignored for alibrary module."
		);
		esp = reader.readNextInt();
		dt.add(
			DWORD, 4, "esp", 
			"Starting stack address of module."
		);
		pageSize = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_esp", 
			"The size of one page for this system."
		);
		lastPageSize = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_lastpagesize", 
			"Bytes on last page (only LE) / Page offset shift (LX)"
		);
		fixupSectionSize = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_fixupsize", 
			"Total size of the fixup information in bytes. This includes the following 4 tables:Fixup Page TableFixup Record TableImport Module name TableImport Procedure Name Table"
		);
		fixupSectionChecksum = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_fixupsum", 
			"Checksum for fixup information. If the checksum feature is not implemented, then the linker will set these fields to zero."
		);
		loaderSectionSize = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_ldrsize", 
			"Flag bits for the module."
		);
		loaderSectionChecksum = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_ldrsum", 
			"Checksum for loader section. If the checksum feature is not implemented, then the linker will set these fields to zero."
		);
		objectTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_objtab", 
			"Object Table offset. This offset is relative to the beginning of the linear EXE header. This offset alsopoints to the start of the Loader Section."
		);
		objectCount = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_objcnt", 
			"# of entries in Object Table."
		);
		pageTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_objmap", 
			"Object Page Table offset. This offset is relative to the beginning of the linear EXE header."
		);
		iterPagesOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_itermap", 
			"Object Iterated Pages offset. This offset is relative to the beginning of the EXE file."
		);
		resourceTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_rsrctab", 
			"Resource Table offset. This offset is relative to the beginning of the linear EXE header."
		);
		resourceCount = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_rsrccnt", 
			"# of entries in Resource Table."
		);
		residentNameTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_restab", 
			"Resident Name Table offset. This offset is relative to the beginning of the linear EXE header."
		);
		entryTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_enttab", 
			"Entry Table offset. This offset is relative to the beginning of the linear EXE header."
		);
		directivesTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_dirtab", 
			"Module Format Directives Table offset.This offset is relative to the beginning of the linear EXE header."
		);
		directivesCount = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_dircnt", 
			"# of Module Format Directives in the Table.This field specifies the number of entries in the Module Format Directives Table. "
		);
		fixupPageTableOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_fpagetab", 
			"Fixup Page Table offset. This offset is relative to the beginning of the linear EXE header. This offset alsopoints to the start of the Fixup Section."
		);
		fixupRecordTableOffset =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_frectab", 
			"Fixup Record Table Offset. This offset is relative to the beginning of the linear EXE header"
		);
		importModuleNameTableOffset =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_impmod", 
			"Import Module Name Table offset.This offset is relative to the beginning of the linear EXE header."
		);
		importModuleNameCount =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_impmodcnt", 
			"# of entries in the Import Module Name Table"
		);
		importProcedureNameTableOffset =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_impproc", 
			"Import Procedure Name Table offset. This offset is relative to the beginning of the linear EXE header."
		);
		checksumTableOffset =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_pagesum", 
			"Per-Page Checksum Table offset.This offset is relative to the beginning of the linear EXE header."
		);
		dataPagesOffset = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_datapage", 
			"Data Pages Offset. This offset is relative to the beginning of the EXE file. This offset also points to thestart of the Data Section."
		);
		preloadPagesCount =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_preload", 
			"# of Preload pages for this module.Note: OS/2 2.0 does not respect the preload of pages as specified in theexecutable file for performance reasons."
		);
		nameTableOffset =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_nrestab", 
			"Non-Resident Name Table offset. This offset is relative to the beginning of the EXE file"
		);
		nameTableLength =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_cbnrestab", 
			"# of bytes in the Non-resident name table"
		);
		nameTableChecksum =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_nressum", 
			"Non-Resident Name Table Checksum"
		);
		autoDataSegmentObjectNumber =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_autodata", 
			"Auto Data Segment Object number.This is the object number for the Auto Data Segment used by 16-bit modules. Thisfield is supported for 16-bit compatibility only and is not used by 32-bit modules."
		);
		debugOffset =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_debuginfo", 
			"Debug Information offset. This offset is relative to the beginning of the file. This offset also points to the start of theDebug Section."
		);
		debugLength =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_debuglen", 
			"Debug Information length"
		);
		pagesInPreloadSectionCount =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_instpreload", 
			"# of instance data pages found in the preload section."
		);
		pagesInDemandSectionCount =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_instdemand", 
			"# of instance data pages found in the demand section."
		);
		heapSize =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_heapsize", 
			"Heap size added to the Auto DS Object"
		);
		stackSize =  reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_stacksize", 
			"Stack size"
		);
		res3 = reader.readNextByteArray(8);
		dt.add(new ArrayDataType(BYTE, 8, 0), "e32_res3", "reserved");
		winresoff = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_winresoff  ", 
			""
		);
		winreslen = reader.readNextInt();
		dt.add(
			DWORD, 4, "e32_winreslen ", 
			""
		);
		Dev386_Device_ID = reader.readNextShort();
		dt.add(
			WORD, 2, "Dev386_Device_ID", 
			""
		);
		Dev386_DDK_Version = reader.readNextShort();
		dt.add(
			WORD, 2, "Dev386_DDK_Version", 
			""
		);
		reader.setPointerIndex(oldIndex);
	}
	
	public boolean isVxD() {
    	if (!isLe()) {
    		return false;
    	}
    	// Guess VxD from module type and missing eip
    	return (moduleFlags & LinearHeader.MODULE_TYPE_MASK) == LinearHeader.MODULE_VXD && eipObject == 0;
	}

	public String getTypePrefix() {
		if (isLx()) {
			return "lx";
		}
		if (isLc()) {
			return "lc";
		}
		return "le";
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return dt;
	}
}
