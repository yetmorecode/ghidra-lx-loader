package yetmorecode.ghidra.format.lx.datatype;

import java.io.IOException;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.UsrException;
import yetmorecode.ghidra.format.lx.LoaderOptions;
import yetmorecode.ghidra.format.lx.model.LxExecutable;
import yetmorecode.ghidra.format.lx.model.ObjectTableEntry;

public class ObjectFixupsType extends StructureDataType {

	public ObjectFixupsType(LxExecutable executable, ObjectTableEntry object, LoaderOptions options, Category cat, Program program) throws UsrException, IOException {
		super(String.format("%08x_%d", options.getBaseAddress(object), object.number), 0);
		setCategoryPath(cat.getCategoryPath());
		for (int i = 0; i < object.pageCount; i++) {
			var page = object.pageTableIndex + i;
			if (executable.fixups.get(page).size() > 0) {
				var sub = new StructureDataType(String.format("%08x", options.getBaseAddress(object) + i*0x1000), 0);
				sub.setCategoryPath(new CategoryPath(
					String.format(
						"%s/%08x",
						cat.getCategoryPathName(),
						options.getBaseAddress(object) + (page-1)*0x1000
					)
				));
				add(sub, "page_" + page, "Page #" + page + " fixups");
				for (var f : executable.fixups.get(page)) {
					var fixupData = f.toDataType();
					fixupData.setCategoryPath(new CategoryPath(
						String.format(
							"%s/%08x/%08x",
							cat.getCategoryPathName(),
							options.getBaseAddress(object) + i*0x1000,
							f.getSourceAddress()
						)
					));
					sub.add(fixupData, "fix_" + f.index, "Fixup record #" + f.index);
					if (options.createFixupLabels) {
						program.getSymbolTable().createLabel(
							program.getAddressFactory().getDefaultAddressSpace().getAddress(f.getSourceAddress()), 
							String.format("fix_%s_%08x", f.shortname(), f.getSourceAddress()), 
							SourceType.ANALYSIS
						);	
					}
				}	
			}
		}
	}

}
