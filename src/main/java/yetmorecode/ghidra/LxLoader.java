package yetmorecode.ghidra;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

import generic.continues.ContinuesFactory;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.data.ArrayDataType;
import yetmorecode.file.format.lx.LxFixupRecord;
import yetmorecode.ghidra.format.lx.InvalidHeaderException;
import yetmorecode.ghidra.format.lx.LoaderOptions;
import yetmorecode.ghidra.format.lx.datatype.FixupSectionType;
import yetmorecode.ghidra.format.lx.datatype.LoaderSectionType;
import yetmorecode.ghidra.format.lx.model.FixupRecord;
import yetmorecode.ghidra.format.lx.model.LxExecutable;
import yetmorecode.ghidra.format.lx.model.ObjectTableEntry;
import yetmorecode.ghidra.format.lx.model.PageMapEntry;

/**
 * LxLoader - LX/LE/LC executable format loader
 * 
 * This loader is able to to load executable files of the LX/LE/LC format.
 * 
 * Linear Executable is an executable file format. 
 * It is used by OS/2, MS-DOS (DOS extender), and by MS Windows VxD files. 
 * It is a successor to NE (New Executable). 
 * There are two main varieties of it: LX (32-bit), and LE (mixed 16/32-bit).
 * LC variety is using compression (hence the C).
 * 
 * @author yetmorecode@posteo.net
 */
public class LxLoader extends AbstractLibrarySupportLoader {
	private String name = "Linear Executable (LX/LE/LC)";
	
	private MessageLog messageLog;
	private LoaderOptions loaderOptions = new LoaderOptions();
	
	@Override
	public String getName() {
		return name;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		try {
			LxExecutable.checkProvider(RethrowContinuesFactory.INSTANCE, provider);
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("x86:LE:32:default", "borlandcpp"), true));
			//loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("x86:LE:32:default", "gcc"), true));
		} catch (IOException e) {
			Msg.error(this, String.format("IOException while reading LxExecutable: %s", e.getMessage()));
			e.printStackTrace();
		} catch (InvalidHeaderException e) {
			// Everything is ok, but the provided data is not a valid LX/LE/LC
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		if (monitor.isCancelled()) {
			return;
		}
		messageLog = log;
		messageLog.clear();
		log(" ⏳ Loading '%s'", program.getDomainFile());
		
		// Try parsing the executable
		int id = program.startTransaction("➔ Loading..");
		monitor.setMessage(String.format("➔ Processing %s", getName()));
		ContinuesFactory factory = MessageLogContinuesFactory.create(messageLog);
		boolean success = false;
		try {
			// Parse EXE from file
			var executable = new LxExecutable(factory, provider, loaderOptions);
			
			// Map IMAGE data (MZ, LX)
			createImageMappings(executable, program, provider, monitor);
			
			// Map objects
			createObjects(executable, program, monitor);
			
			// Add entrypoint, disassemble, ..
			createEntrypoint(executable, program, monitor);
			
			success = true;
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			program.endTransaction(id, success);
		}
	}
	
	/**
	 * Creates MZ and LE exe image memory block (in OTHER space) and types the data
	 * 
	 * LE have 4 regions:
	 * - header (aka information section)
	 * - loader section
	 * - fixup section
	 * - data pages section
	 */
	private void createImageMappings(LxExecutable executable, Program program, ByteProvider provider, TaskMonitor monitor) throws CancelledException, IOException, AddressOverflowException, UsrException {
		var header = executable.getLeHeader();
		var dosHeader = executable.getDosHeader();
		var fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		Address addr;
		MemoryBlock b;
		
		monitor.setMessage(String.format("➔ Mapping Image data", executable.getLeHeader().getTypePrefix().toUpperCase()));
		
		// MZ image
		if (loaderOptions.mapMZ) {
			addr = AddressSpace.OTHER_SPACE.getAddress(0);
			b = MemoryBlockUtils.createInitializedBlock(
				program, 
				true, 
				".mz", addr, 
				fileBytes, 0, dosHeader.toDataType().getLength(), 
				"Old MZ-style image (headers + stub)", 
				null, 
				true, false, false, 
				null
			);
			createData(program, b.getStart(), dosHeader.toDataType());
			program.getSymbolTable().createLabel(b.getStart(), "IMAGE_MZ_HEADER", SourceType.ANALYSIS);
			log(" ✓ Mapped MZ Header");
		}
			
		// LE header
		if (loaderOptions.mapLX) {
			addr = AddressSpace.OTHER_SPACE.getAddress(dosHeader.e_lfanew());
			
			var size = header.dataPagesOffset - dosHeader.e_lfanew();
			if (loaderOptions.mapDataSection) {
				size += (header.pageCount-1) * header.pageSize + header.lastPageSize;
			}
			
			b = MemoryBlockUtils.createInitializedBlock(
				program, 
				true, 
				String.format(".%s", header.getTypePrefix()), addr, 
				fileBytes, dosHeader.e_lfanew(), size, 
				"Linear Executable Information", 
				null, 
				true, false, false, 
				null
			);
			createData(program, b.getStart(), header.toDataType());
			program.getSymbolTable().createLabel(b.getStart(), "IMAGE_LE_HEADER", SourceType.ANALYSIS);
			log(" ✓ Mapped LX Header Section");
			
			// LE loader section
			if (loaderOptions.mapLoaderSection) {
				addr = b.getStart().add(header.objectTableOffset);
				monitor.setMessage(String.format("➔ Mapping LX Loader section"));
				createData(
					program, 
					addr,
					new LoaderSectionType(executable, header.fixupPageTableOffset - header.objectTableOffset)
				);
				program.getSymbolTable().createLabel(addr, "IMAGE_LE_LOADER", SourceType.ANALYSIS);
				log(" ✓ Mapped LX Loader Section");
			}
				
			// LE fixup section
			if (loaderOptions.mapFixupSection) {
				var dm = program.getDataTypeManager();
				var cat = dm.createCategory(new CategoryPath("/_le/_fixup"));
				addr = b.getStart().add(header.fixupPageTableOffset);
				monitor.setMessage(String.format("➔ Mapping LX Fixup Section (%d fixups total)", executable.fixupCount));
				var dt = new FixupSectionType(
					executable, 
					header.dataPagesOffset - dosHeader.e_lfanew() - header.fixupPageTableOffset,
					loaderOptions,
					cat,
					program
				);
				createData(program, addr, dt);
				program.getSymbolTable().createLabel(addr, "IMAGE_LE_FIXUP", SourceType.ANALYSIS);
				log(" ✓ Mapped LX Fixup Section");
			}
			
			// LE Data Section
			if (loaderOptions.mapDataSection) {
				addr = b.getStart().add(header.dataPagesOffset - dosHeader.e_lfanew());
				monitor.setMessage(String.format("➔ Mapping data pages (%d total)", executable.header.pageCount));
				program.getSymbolTable().createLabel(addr, "IMAGE_LE_DATA", SourceType.ANALYSIS);
				
				var all = new StructureDataType("IMAGE_LE_DATA", 0);
				
				// Full size pages
				for (var i = 0; i < executable.header.pageCount-1; i++) {
					var dt = new ArrayDataType(StructConverter.BYTE, header.pageSize, 0); 
					addr = b.getStart().add(header.dataPagesOffset + i * header.pageSize - dosHeader.e_lfanew());
					all.add(dt, "page_" + (i+1), "");
				}
				// Last page
				var dt = new ArrayDataType(StructConverter.BYTE, header.lastPageSize, 0);
				all.add(dt, "page_" + header.pageCount, "");
				
				addr = b.getStart().add(header.dataPagesOffset - dosHeader.e_lfanew());
				createData(program, addr, all);
				log(" ✓ Mapped LX Data Section");
			}
		}
	}
	
	private void createObjects(LxExecutable executable, Program program, TaskMonitor monitor) throws IOException, UsrException {
		// Map each object
		var space = program.getAddressFactory().getDefaultAddressSpace();
		for (var object : executable.getObjects()) {
			monitor.setMessage(String.format("➔ Mapping .object%d", object.number));
			byte[] block = createObjectBlock(program, executable, object, object.number == executable.getObjects().size());
			program.getMemory().createInitializedBlock(
				".object" + object.number, 
				space.getAddress(loaderOptions.getBaseAddress(object)), 
				new ByteArrayInputStream(block), 
				object.size, 
				monitor, false
			);
		}
	}
	
	private Data createData(Program program, Address address, DataType dt) {
		try {
			Data d = program.getListing().getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				program.getListing().createData(address, dt);
			}
			return d;
		}
		catch (CodeUnitInsertionException e) {
			Msg.warn(this, "LX data markup conflict at " + address + ": " + e.getMessage());
			e.printStackTrace();
		}
		catch (DataTypeConflictException e) {
			Msg.error(this, "LX data type markup conflict at " + address + ": " + e.getMessage());
			e.printStackTrace();
		}
		return null;
	}
	
	private byte[] createObjectBlock(Program program, LxExecutable le, ObjectTableEntry object, boolean isLastObject) throws IOException, UsrException {
		var header = le.getLeHeader();
		var pageMapOffset = le.getDosHeader().e_lfanew() + header.pageTableOffset;
		var pageSize = header.pageSize; 
		var space = program.getAddressFactory().getDefaultAddressSpace();
		
		// Temporary memory to assemble all pages to one block
		byte block[] = new byte[object.size+4096];
		var blockIndex = 0;
		
		// Some statistics on fixups
		int fixupCount = 0;
		int fixupsHandled = 0;
		int fixupsUnhandled = 0;
		int fixupsByType[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		
		
		// Loop through all pages for this object, apply fixups per page and add them together
		for (var i = 0; i < object.pageCount; i++) {
			// Page map indices are one-based 
			var index = object.pageTableIndex + i;
			
			PageMapEntry entry = new PageMapEntry(le.getReader(), pageMapOffset + (index-1) * 4);
			var pageOffset  = header.dataPagesOffset + (entry.getIndex()-1)*pageSize;

			// Create a label for each page
			if (loaderOptions.createPageLabels) {
				program.getSymbolTable().createLabel(
					space.getAddress(loaderOptions.getBaseAddress(object) + blockIndex), 
					"LE_PAGE_" + index, 
					SourceType.ANALYSIS
				);
			}
			
			// Read page from file
			FactoryBundledWithBinaryReader r = le.getReader();
			r.setPointerIndex(pageOffset);
			byte[] pageData;
			var isLastPage = i == object.pageCount - 1;
			if (isLastObject && isLastPage) {
				pageData = r.readNextByteArray(header.lastPageSize);
			} else {
				pageData = r.readNextByteArray(pageSize);	
			}
			
			// Apply fixups to page
			for (var f : le.fixups.get(index)) {
				// Apply the actual fixup
				int base = loaderOptions.getBaseAddress(le.getObjects().get(f.objectNumber-1));
				fixupsByType[f.getSourceType()]++;
				if (f.getSourceType() == LxFixupRecord.SOURCE_32BIT_OFFSET_FIXUP) {
					int value = base + f.targetOffset;
					if (loaderOptions.logOffsets32bit) {
						Msg.debug(this, String.format(
							"32-bit offset fixup #%x at %08x (page %03x) -> %x (object #%x, target flags: %2x)",
							fixupCount, 
							loaderOptions.getBaseAddress(object) + i*pageSize + f.sourceOffset,
							index,
							value, f.objectNumber,
							f.targetFlags
						));
						fixupCount++;
					}
					if (f.sourceOffset >= 0 && f.sourceOffset < pageData.length) {
						pageData[f.sourceOffset] = (byte)(value & 0xff);
					}
					if (f.sourceOffset+1 >= 0 && f.sourceOffset+1 < pageData.length) {
						pageData[f.sourceOffset+1] = (byte)((value & 0xff00)>>8);						
					}
					if (f.sourceOffset+2 >= 0 && f.sourceOffset+2 < pageData.length) {
						pageData[f.sourceOffset+2] = (byte)((value & 0xff0000)>>16);
					}
					if (f.sourceOffset+3 >= 0 && f.sourceOffset+3 < pageData.length) {
						pageData[f.sourceOffset+3] = (byte)((value & 0xff000000)>>24);
					}
					fixupsHandled++;
				} else if (f.getSourceType() == LxFixupRecord.SOURCE_16BIT_OFFSET_FIXUP) {
					int value = base + f.targetOffset;
					if (loaderOptions.logOffsets16bit) {
						Msg.debug(this, String.format(
							"16-bit offset fixup #%x at %08x (page %03x) -> %x (object #%x, target flags: %2x %s)",
							fixupCount, 
							loaderOptions.getBaseAddress(object) + i*pageSize + f.sourceOffset,
							index,
							value, f.objectNumber,
							f.targetFlags, ""
						));
						fixupCount++;
					}
					if (f.sourceOffset >= 0 && f.sourceOffset < pageData.length) {
						pageData[f.sourceOffset] = (byte)(value & 0xff);
					}
					if (f.sourceOffset+1 >= 0 && f.sourceOffset+1 < pageData.length) {
						pageData[f.sourceOffset+1] = (byte)((value & 0xff00)>>8);						
					}
					fixupsHandled++;
				} else if (f.getSourceType() == LxFixupRecord.SOURCE_32BIT__SELF_REF_OFFSET_FIXUP) {
					int value = base + f.targetOffset;
					if (loaderOptions.logSelfRel) {
						Msg.debug(this, String.format(
							"32-bit self-ref fixup #%x at %08x (page %03x) -> %x (object #%x, target flags: %2x %s)",
							fixupCount, 
							loaderOptions.getBaseAddress(object) + i*pageSize + f.sourceOffset,
							index,
							value, f.objectNumber,
							f.targetFlags, ""
						));
						fixupCount++;
					}
					long address = loaderOptions.getBaseAddress(object) + i*pageSize + f.sourceOffset;
					value = (int) (value - address - 4);
					if (f.sourceOffset >= 0 && f.sourceOffset < pageData.length) {
						pageData[f.sourceOffset] = (byte)(value & 0xff);
					}
					if (f.sourceOffset+1 >= 0 && f.sourceOffset+1 < pageData.length) {
						pageData[f.sourceOffset+1] = (byte)((value & 0xff00)>>8);						
													}
					if (f.sourceOffset+2 >= 0 && f.sourceOffset+2 < pageData.length) {
						pageData[f.sourceOffset+2] = (byte)((value & 0xff0000)>>16);
					}
					if (f.sourceOffset+3 >= 0 && f.sourceOffset+3 < pageData.length) {
						pageData[f.sourceOffset+3] = (byte)((value & 0xff000000)>>24);
					}
					fixupsHandled++;
				} else if (f.getSourceType() == LxFixupRecord.SOURCE_1616PTR_FIXUP) {
					if (loaderOptions.log1616pointer) {
						Msg.debug(this, String.format(
							"16:16 pointer fixup #%x at %08x (page %03x) -> %02x:%04x (target flags: %2x %s) %2x %2x %2x %2x",
							fixupCount, 
							loaderOptions.getBaseAddress(object) + i*pageSize + f.sourceOffset,
							index,
							base, f.targetOffset,
							f.targetFlags, "",
							pageData[f.sourceOffset],
							pageData[f.sourceOffset+1],
							pageData[f.sourceOffset+2],
							pageData[f.sourceOffset+3]
						));
						fixupCount++;
					}
					if (f.sourceOffset >= 0 && f.sourceOffset < pageData.length) {
						pageData[f.sourceOffset] = (byte)(base & 0xff);
					}
					if (f.sourceOffset+1 >= 0 && f.sourceOffset+1 < pageData.length) {
						pageData[f.sourceOffset+1] = (byte)((base & 0xff00)>>8);						
					}
					if (f.sourceOffset+2 >= 0 && f.sourceOffset+2 < pageData.length) {
						pageData[f.sourceOffset+2] = (byte)(f.targetOffset & 0xff);
					}
					if (f.sourceOffset+3 >= 0 && f.sourceOffset+3 < pageData.length) {
						pageData[f.sourceOffset+3] = (byte)((f.targetOffset & 0xff00)>>8);
					}
					fixupsHandled++;
				} else if (f.getSourceType() == LxFixupRecord.SOURCE_16BIT_SELECTOR_FIXUP) {
					// 16 bit selector fixup
					fixupsHandled++;
				} else {
					Msg.warn(this, String.format(
						"WARNING: unhandled fixup #%x_%s at %08x (type %02x, page %03x): %s -> object#%x:%x",
						f.index, f.shortname(),  f.getSourceAddress(),
						index,
						f.hasSourceList() ? "source list " + f.sourceCount : String.format("%x", f.sourceOffset),
						f.objectNumber, f.targetOffset
					));
					fixupCount++;
					fixupsUnhandled++;
				}
			}
			
			// Copy page into object block
			System.arraycopy(pageData, 0, block, blockIndex, pageData.length);
			blockIndex += pageSize;
		}
		
		log(" ✓ Mapped .object%d into memory: %08x - %08x [%08x] (selector %03x)", 
			object.number, 
			loaderOptions.getBaseAddress(object),
			loaderOptions.getBaseAddress(object) + object.size,
			object.size,
			loaderOptions.getSelector(object)
		);
		
		// Log fixup statistics
		if (loaderOptions.logFixupStats) {
			ArrayList<String> byType = new ArrayList<>();
			for (int i = 0; i < 9; i++) {
				if (fixupsByType[i] > 0) {
					byType.add(String.format("%s: %d", FixupRecord.shortnames[i], fixupsByType[i]));
				}
			}
			if (fixupsHandled + fixupsUnhandled > 0) {
				log(
					"   ♘ %d fixups [%s]",
					fixupsHandled + fixupsUnhandled,
					String.join(", ", byType)
				);
			}
		}
		return block;
	}
	
	private void createEntrypoint(LxExecutable executable, Program program, TaskMonitor monitor) {
		// Initialization (entry point, disassemble, ...)
		if (!loaderOptions.omitEntry) {
			monitor.setMessage(String.format("➔ Setting entrypoint"));
			var api = new FlatProgramAPI(program, monitor);
			int eip = executable.getLeHeader().eip;
			var eipObject = executable.getObjects().get(executable.getLeHeader().eipObject-1);
			eip += loaderOptions.getBaseAddress(eipObject);			
			log(" ✓ Entrypoint set @ %08x [base %08x + eip %08x]", 
				eip, 
				loaderOptions.getBaseAddress(eipObject), 
				executable.getLeHeader().eip
			);
			api.addEntryPoint(api.toAddr(eip));
			if (loaderOptions.disassembleEntry) {
				api.disassemble(api.toAddr(eip));	
			}
			api.createFunction(api.toAddr(eip), "_entry");	
		}
	}
	
	private void log(String format, Object... args)  {
		messageLog.appendMsg(String.format(format, args));
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		return loaderOptions.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		loaderOptions.validateOptions(provider, loadSpec, options, program);
		return super.validateOptions(provider, loadSpec, options, program);
	}
}
