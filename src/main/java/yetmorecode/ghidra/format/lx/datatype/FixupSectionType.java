package yetmorecode.ghidra.format.lx.datatype;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.UsrException;
import yetmorecode.ghidra.format.lx.LoaderOptions;
import yetmorecode.ghidra.format.lx.model.LxExecutable;

public class FixupSectionType extends StructureDataType {

	public FixupSectionType(LxExecutable executable, int end, LoaderOptions options, Category cat, Program program) throws UsrException, IOException {
		super("IMAGE_LE_FIXUP", 0);
		
		var h = executable.header;
		add(new ArrayDataType(StructConverter.DWORD, h.pageCount+1, 0), "fixup_page_table", 
			"The Fixup Page Table provides a simple mapping of a logical page number to an offset into "
			+ "the Fixup Record Table for that page. "
			+ "This table is parallel to the Object Page Table, except that there is one additional entry in this "
			+ "table to indicate the end of the Fixup Record Table."
		);
		
		
		
		for (var object : executable.getObjects()) {
			if (executable.objectHasFixups(object)) {
				add(
					new ObjectFixupsType(executable, object, options, cat, program), 
					"fixups_object" + object.number, 
					"Fixup records for object #" + object.number
				);
			}
		}
		
		if (h.importModuleNameCount > 0) {
			add(new ArrayDataType(StructConverter.BYTE, h.importProcedureNameTableOffset - h.importModuleNameTableOffset, 0), "import_module_name", "TODO");
		}
		if (h.dataPagesOffset > h.importProcedureNameTableOffset) {
			add(new ArrayDataType(StructConverter.BYTE, (h.dataPagesOffset - executable.getDosHeader().e_lfanew()) - h.importProcedureNameTableOffset, 0), "import_procedure_table", "TODO");
		}
	}
}
