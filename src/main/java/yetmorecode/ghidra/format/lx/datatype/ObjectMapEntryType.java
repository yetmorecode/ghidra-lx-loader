package yetmorecode.ghidra.format.lx.datatype;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.StructureDataType;

public class ObjectMapEntryType extends StructureDataType {
	public ObjectMapEntryType() {
		super("object_entry", 0);
		add(
			StructConverter.DWORD, 4, "size", 
			"Virtual size of object. This is the size of the object that will be allocated when the object is loaded. Theobject data length must be less than or equal to the total size of the pages in theEXE file for the object. This memory size must also be large enough to contain all ofthe iterated data and uninitialized data in the EXE file"
		);
		add(
			StructConverter.DWORD, 4, "base", 
			"Base address the object is relocated to"
		);
		add(
			StructConverter.DWORD, 4, "flags", 
			"Object flags. 0001h = Readable Object.0002h = Writable Object.0004h = Executable Object.The readable, writable and executable flags provide support for all possible protections.In systems where all of these protections are not supported, the loader will be responsiblefor making the appropriate protection match for the system.0008h = Resource Object.0010h = Discardable Object.0020h = Object is Shared.0040h = Object has Preload Pages.0080h = Object has Invalid Pages.0100h = Object has Zero Filled Pages.0200h = Object is Resident (valid for VDDs, PDDs only).0300h = Object is Resident & Contiguous (VDDs, PDDs only).0400h = Object is Resident & 'long-lockable' (VDDs, PDDs only).0800h = Reserved for system use.1000h = 16:16 Alias Required (80x86 Specific).2000h = Big/Default Bit Setting (80x86 Specific).The 'big/default' bit, for data segments, controls the setting of the Big bit in the segment descriptor.(The Big bit, or B-bit, determines whether ESP or SP is used as the stack pointer.)For code segments, this bit controls the setting of the Default bit in the segment descriptor.(The Default bit, or D-bit, determines whether the default word size is 32-bits or 16-bits.It also affects the interpretation of the instruction stream.)4000h = Object is conforming for code (80x86 Specific).8000h = Object I/O privilege level (80x86 Specific). Only used for 16:16 Alias Objects."
		);
		add(
			StructConverter.DWORD, 4, "pageTableIndex", 
			"Object Page Table Index.This specifies the number of the first object page table entry for this object.The object page table specifies where in the EXE file a page can be found for agiven object and specifies per-page attributes.The object table entries are ordered by logical page in the object table.In other words the object table entries are sorted based on the object page table index value"
		);
		add(
			StructConverter.DWORD, 4, "pageCount", 
			"# of object page table entries for this object.Any logical pages at the end of an object that do not have an entry in the object pagetable associated with them are handled as zero filled or invalid pages by the loader.When the last logical pages of an object are not specified with an object page tableentry, they are treated as either zero filled pages or invalid pages based on the lastentry in the object page table for that object.If the last entry was neither a zero filled or invalid page, then theadditional pages are treated as zero filled pages"
		);
		add(
			StructConverter.DWORD, 4, "reserved", 
			""
		);
		
	}

}
