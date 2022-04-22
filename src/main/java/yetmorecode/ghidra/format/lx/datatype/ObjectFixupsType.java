package yetmorecode.ghidra.format.lx.datatype;

import java.io.IOException;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.MemReferenceImpl;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.UsrException;
import yetmorecode.file.format.lx.LinearObjectTableEntry;
import yetmorecode.ghidra.format.lx.model.Executable;
import yetmorecode.ghidra.format.lx.model.FixupRecord;
import yetmorecode.ghidra.lx.Options;

public class ObjectFixupsType extends StructureDataType {

	public ObjectFixupsType(Executable executable, LinearObjectTableEntry object, Options options, Category cat, Program program, MemoryBlock b) throws UsrException, IOException {
		super(String.format("%08x_%d", options.getBaseAddress(object), object.number), 0);
		setCategoryPath(cat.getCategoryPath());
		
		// Iterate over all object pages
		for (int i = 0; i < object.pageCount; i++) {
			var page = object.pageTableIndex + i;
			var pageSize = executable.header.pageSize;
			
			// If page has fixups
			if (executable.fixups.get(page).size() > 0) {
				var sub = new StructureDataType(String.format("%08x", options.getBaseAddress(object) + i*pageSize), 0);
				sub.setCategoryPath(new CategoryPath(
					String.format(
						"%s/%08x",
						cat.getCategoryPathName(),
						options.getBaseAddress(object) + (page-1)*pageSize
					)
				));
				add(sub, "page_" + page, "Page #" + page + " fixups");
				
				// Each single fixup
				var current = 0;
				for (var fix : executable.fixups.get(page)) {
					var f = (FixupRecord)fix;
					// Add datatype
					var fixupData = f.toDataType();
					
					fixupData.setCategoryPath(new CategoryPath(
						String.format("%s/%08x/%08x",
							cat.getCategoryPathName(),
							options.getBaseAddress(object) + i*pageSize,
							f.getSourceAddress()
						)
					));
					sub.add(fixupData, "fix_" + f.index, "Fixup record #" + f.index);
					
					// Add xref
					var to = b.getStart().add(executable.header.dataPagesOffset - executable.lfanew + (page-1)*pageSize + current);
					var space = program.getAddressFactory().getDefaultAddressSpace();
					var ref = new MemReferenceImpl(
						space.getAddress(f.getSourceAddress()), 
						to, 
						RefType.DATA_IND, 
						SourceType.ANALYSIS, 
						0, 
						false
					);
					program.getReferenceManager().addReference(ref);
					
					current += fixupData.getLength();
				}	
			}
		}
	}
}
