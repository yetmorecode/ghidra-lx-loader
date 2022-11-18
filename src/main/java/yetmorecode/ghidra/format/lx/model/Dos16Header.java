package yetmorecode.ghidra.format.lx.model;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import yetmorecode.file.format.dos16m.BwHeader;
import yetmorecode.ghidra.lx.InvalidHeaderException;

public class Dos16Header extends BwHeader implements StructConverter {
	public final static String DATATYPE_NAME = "IMAGE_DOS16_HEADER";
	
	private StructureDataType dt = new StructureDataType(DATATYPE_NAME, 0);
	
	public Dos16Header(BinaryReader reader, long index) throws IOException, InvalidHeaderException {
		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(index);

		signature = reader.readNextShort();
		dt.add(new ArrayDataType(ASCII,2,1), "signature", "Magic number for DOS/16 BW");
		if (signature != DOS16M_SIGNATURE) {
			throw new InvalidHeaderException("Not a DOS/16 BW Header");
		}
		last_page_bytes = reader.readNextShort();
		dt.add(WORD, 2, "last_page_bytes", "length of image mod 512");
		pages_in_file = reader.readNextShort();
		dt.add(WORD, 2, "pages_in_file", "number of 512 byte pages");
		reserved1 = reader.readNextShort();
		dt.add(WORD, 2, "reserved1", "");
		reserved2 = reader.readNextShort();
		dt.add(WORD, 2, "reserved2", "");
		min_alloc = reader.readNextShort();
		dt.add(WORD, 2, "min_alloc", "required memory, in KB");
		max_alloc = reader.readNextShort();
		dt.add(WORD, 2, "max_alloc", "max KB (private allocation)");
		stack_seg = reader.readNextShort();
		dt.add(WORD, 2, "stack_seg", "segment of stack");
		stack_ptr = reader.readNextShort();
		dt.add(WORD, 2, "stack_ptr", "initial SP value");
		first_reloc_sel = reader.readNextShort();
		dt.add(WORD, 2, "first_reloc_sel", "huge reloc list selector");
		init_ip = reader.readNextShort();
		dt.add(WORD, 2, "init_ip", "initial IP value");
		code_seg = reader.readNextShort();
		dt.add(WORD, 2, "code_seg", "segment of code");
		runtime_gdt_size = reader.readNextShort();
		dt.add(WORD, 2, "runtime_gdt_size", "runtime GDT size in bytes");
		MAKEPM_version = reader.readNextShort();
		dt.add(WORD, 2, "MAKEPM_version", "ver * 100, GLU = (ver+10)*100");
		next_header_pos = reader.readNextInt();
		dt.add(DWORD, 4, "next_header_pos", "file pos of next spliced .EXP");
		cv_info_offset = reader.readNextInt();
		dt.add(DWORD, 4, "cv_info_offset", "offset to start of debug info");
		last_sel_used = reader.readNextShort();
		dt.add(WORD, 2, "last_sel_used", "last selector value used");
		pmem_alloc = reader.readNextShort();
		dt.add(WORD, 2, "pmem_alloc", "private xm amount KB if nonzero");
		alloc_incr = reader.readNextShort();
		dt.add(WORD, 2, "alloc_incr", "auto ExtReserve amount, in KB");
		dt.add(new ArrayDataType(BYTE,6,1), "reserved4", "");
		options = reader.readNextShort();
		dt.add(WORD, 2, "options", "runtime options");
		trans_stack_sel = reader.readNextShort();
		dt.add(WORD, 2, "trans_stack_sel", "sel of transparent stack");
		exp_flags = reader.readNextShort();
		dt.add(WORD, 2, "exp_flags", "see ef_ constants below");
		program_size = reader.readNextShort();
		dt.add(WORD, 2, "program_size", "size of program in paras (16 byte blocks)");
		gdtimage_size = reader.readNextShort();
		dt.add(WORD, 2, "gdtimage_size", "size of gdt in file (bytes) ");
		first_selector = reader.readNextShort();
		dt.add(WORD, 2, "first_selector", "gdt[first_sel] = gdtimage[0], 0 => 0x80");
		default_mem_strategy = reader.readNextByte();
		dt.add(BYTE, 1, "default_mem_strategy", "");
		dt.add(BYTE, 1, "reserved5", "");
		transfer_buffer_size = reader.readNextShort();
		dt.add(WORD, 2, "transfer_buffer_size", "default in bytes, 0 => 8KB");
		dt.add(new ArrayDataType(BYTE,48,1), "reserved6", "");
		dt.add(new ArrayDataType(ASCII,48,1), "EXP_path", "original .EXP file name");
		
		reader.setPointerIndex(oldIndex);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return dt;
	}
}
