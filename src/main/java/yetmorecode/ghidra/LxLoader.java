package yetmorecode.ghidra;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
import ghidra.program.database.mem.FileBytes;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;
import yetmorecode.file.format.lx.LxFixupRecord;
import yetmorecode.file.format.lx.LxHeader;
import yetmorecode.ghidra.format.lx.LxExecutable;
import yetmorecode.ghidra.format.lx.ObjectTableEntry;
import yetmorecode.ghidra.format.lx.PageMapEntry;
import yetmorecode.ghidra.format.lx.datatype.FixupSectionType;
import yetmorecode.ghidra.format.lx.datatype.LoaderSectionType;
import yetmorecode.ghidra.format.lx.datatype.ObjectMapEntryType;
import yetmorecode.ghidra.format.lx.exception.InvalidHeaderException;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class LxLoader extends AbstractLibrarySupportLoader {

	private final static String GROUP_OVERRIDES = "Runtime overrides (comma-separated)";
	private final static String GROUP_LOGGING = "Logging";
	private final static String GROUP_INIT = "Initialization";

	private final static String OPTION_LOG_32BIT_OFFSET = "Log 32-bit offset fixups";
	private final static String OPTION_LOG_16BIT_OFFSET = "Log 16-bit offset fixups";
	private final static String OPTION_LOG_32BIT_SELFREL = "Log 32-bit self-rel fixups";
	private final static String OPTION_LOG_1616_POINTER = "Log 16:16 pointer fixups";
	private final static String OPTION_WARN_UNHANDLED_FIXUP = "Warn on unhandled fixups";
	private final static String OPTION_BASE_ADDRESSES = "Object base addresses";
	private final static String OPTION_OBJECT_SELECTORS = "Object segment selectors";
	private final static String OPTION_OMIT_ENTRY = "Omit entry point";
	private final static String OPTION_DISASSEMBLE = "Disassemble from entry";
	
	
	private MessageLog log;
	
	private boolean logOffsets32bit = false;
	private boolean logOffsets16bit = false;
	private boolean logSelfRel = false;
	private boolean log1616pointer = false;
	private boolean warnUnhandled = true;
	private boolean omitEntry = false;
	private boolean disassembleEntry = true;
	
	private int[] baseAddresses;
	private int[] selectors;
	
	private String name = "Linear Executable (LX/LE/LC)";
	
	@Override
	public String getName() {
		return name;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (provider.length() < 4) {
			return loadSpecs;
		}
		try {
			new LxExecutable(RethrowContinuesFactory.INSTANCE, provider);
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("x86:LE:32:default", "borlandcpp"), true));
			//loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("x86:LE:32:default", "gcc"), true));
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidHeaderException e) {
			// Everything is ok, but the provided data is not a valid LX/LE/LC
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog l)
			throws CancelledException, IOException {

		if (monitor.isCancelled()) {
			return;
		}
		log = l;
		monitor.setMessage(String.format("Processing %s..", getName()));
		ContinuesFactory factory = MessageLogContinuesFactory.create(log);
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		LxExecutable executable;
		
		// Try parsing the executable
		int id = program.startTransaction("Loading..");
		boolean success = false;
		try {
			executable = new LxExecutable(factory, provider);

			monitor.setMessage(String.format("Processing %s...", getName()));
			// Map MZ and LE image
			createHeaderTypes(executable, program, provider, monitor);
			
			// Log verbose object table information
			var header = executable.getLeHeader();
			log.appendMsg(String.format("Number of objects: %x", header.objectCount));
			for (var object : executable.getObjects()) {
				log.appendMsg(String.format(
					"Object #%x base: %08x - %08x (%08x), pages: %03x - %03x (%03x total), flags: %s",
					object.number,
					object.base, object.base + object.size, object.size,
					object.pageTableIndex, object.pageTableIndex + object.pageCount - 1, object.pageCount,
					object.getExtraFlagsLabel()
				));
			}
			
			// Map each object
			for (var object : executable.getObjects()) {
				byte[] block = createObjectBlock(executable, object, object.number == executable.getObjects().size());
				program.getMemory().createInitializedBlock(
					".object" + object.number, 
					space.getAddress(getBaseAddress(object)), 
					new ByteArrayInputStream(block), 
					object.size, 
					monitor, false
				);
			}
			
			// Initialization (entry point, disassemble, ...)
			if (!omitEntry) {
				var api = new FlatProgramAPI(program, monitor);
				int eip = executable.getLeHeader().eip;
				var o = executable.getObjects().get(executable.getLeHeader().eipObject-1);
				eip += getBaseAddress(o);			
				log.appendMsg(String.format("Entrypoint set at %08x (%08x + %08x)", eip, getBaseAddress(o), executable.getLeHeader().eip));
				api.addEntryPoint(api.toAddr(eip));
				if (disassembleEntry) {
					api.disassemble(api.toAddr(eip));	
				}
				api.createFunction(api.toAddr(eip), "_entry");	
			}
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
	private void createHeaderTypes(LxExecutable executable, Program program, ByteProvider provider, TaskMonitor monitor) throws CancelledException, IOException, AddressOverflowException, UsrException {
		var header = executable.getLeHeader();
		var dosHeader = executable.getDosHeader();
		var fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		
		// MZ image
		Address addr = AddressSpace.OTHER_SPACE.getAddress(0);
		var b = MemoryBlockUtils.createInitializedBlock(
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
		
		// LE header
		addr = AddressSpace.OTHER_SPACE.getAddress(dosHeader.e_lfanew());
		b = MemoryBlockUtils.createInitializedBlock(
			program, 
			true, 
			String.format(".%s", header.getTypePrefix()), addr, 
			fileBytes, dosHeader.e_lfanew(), header.dataPagesOffset - dosHeader.e_lfanew(), 
			"Linear Executable Information", 
			null, 
			true, false, false, 
			null
		);
		createData(program, b.getStart(), header.toDataType());
		program.getSymbolTable().createLabel(b.getStart(), "IMAGE_LE_HEADER", SourceType.ANALYSIS);
		
		// LE loader section
		addr = b.getStart().add(header.objectTableOffset);
		createData(
			program, 
			addr,
			new LoaderSectionType(executable, header.fixupPageTableOffset - header.objectTableOffset)
		);
		program.getSymbolTable().createLabel(addr, "IMAGE_LE_LOADER", SourceType.ANALYSIS);
		
		// LE fixup section 
		addr = b.getStart().add(header.fixupPageTableOffset);
		createData(
			program, 
			addr,
			new FixupSectionType(executable, header.dataPagesOffset - dosHeader.e_lfanew() - header.fixupPageTableOffset)
		);
		program.getSymbolTable().createLabel(addr, "IMAGE_LE_FIXUP", SourceType.ANALYSIS);
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
		}
		catch (DataTypeConflictException e) {
			Msg.error(this, "LX data type markup conflict at " + address + ": " + e.getMessage());
		}
		return null;
	}
	
	private byte[] createObjectBlock(LxExecutable le, ObjectTableEntry object, boolean isLastObject) throws IOException {
		// Temporary memory to assemble all pages to one block
		byte block[] = new byte[object.size+4096];
		long blockIndex = 0;
		
		var header = le.getLeHeader();
		long pageMapOffset = le.getDosHeader().e_lfanew() + header.pageTableOffset;
		long fixupPageMapOffset = le.getDosHeader().e_lfanew() + header.fixupPageTableOffset;
		long fixupRecordOffset = le.getDosHeader().e_lfanew() + header.fixupRecordTableOffset;
		long pageSize = header.pageSize; 
		
		// Some statistics on fixups
		int fixupCount = 0;
		int fixupsHandled = 0;
		int fixupsUnhandled = 0;
		int fixupsByType[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		
		log.appendMsg(String.format("Mapping Object#%d to %08x - %08x (selector %03x)", 
				object.number, 
				getBaseAddress(object),
				getBaseAddress(object) + object.size,
				getSelector(object)
		));
		
		// Loop through all pages for this object, apply fixups per page and add them together
		for (int j = 0; j < object.pageCount; j++) {
			// Page map indices are one-based, so subtract one 
			long index = object.pageTableIndex + j - 1;
			
			PageMapEntry entry = new PageMapEntry(le.getReader(), (int) (pageMapOffset + index*4));
			
			int fixupBegin = le.getReader().readInt(fixupPageMapOffset + index*4);
			int fixupEnd = le.getReader().readInt(fixupPageMapOffset + index*4 + 4);					
			long pageOffset  = header.dataPagesOffset + (entry.getIndex()-1)*pageSize;

			
			// Read page from file
			FactoryBundledWithBinaryReader r = le.getReader();
			r.setPointerIndex(pageOffset);
			byte[] pageData;
			var isLastPage = j == object.pageCount - 1;
			if (isLastObject && isLastPage) {
				pageData = r.readNextByteArray(header.lastPageSize);
			} else {
				pageData = r.readNextByteArray((int) pageSize);	
			}
			
			// Apply fixups to page
			int fixupDataSize = fixupEnd - fixupBegin;
			if (fixupDataSize > 0) {
				byte fixupData[] = le.getReader().readByteArray(fixupRecordOffset + fixupBegin, fixupDataSize);
				
				int current = 0;
				while (current < fixupDataSize) {
					/**
					 * Fixup Record "SRC / FLAGS / SRCOFF" 
					 */
					
					// SRC
					byte sourceType = fixupData[current];
					
					// FLAGS
					byte targetFlags = fixupData[current+1];
					String targetFlagsLabel = "";
					boolean isSourceList = (sourceType & 0x20) > 0;
					//boolean isSourceAlias = (sourceType & 0x10) > 0;
					boolean is16bitSelectorFixup = (sourceType & 0xf) == 2;
					boolean is32bitTargetOffset = false;
					boolean objectNumber16Bit = false;
					if ((targetFlags & 0x10) > 0) {
						is32bitTargetOffset = true;
						targetFlagsLabel += " 32-bit target offset,";
					} else {
						targetFlagsLabel += " 16-bit target offset,";
					}
					if ((targetFlags & 0x40) > 0) {
						objectNumber16Bit = true;
						targetFlagsLabel += " 16-bit object number,";
					} else {
						targetFlagsLabel += " 8-bit object number,";
					}
					
					// SRCOFF
					byte sourceCount = 0;
					short sourceOffset = 0;
					if (isSourceList) {
						sourceCount = fixupData[current+3];
						current += 3;
					} else {
						ByteBuffer bb = ByteBuffer.allocate(2);
						bb.order(ByteOrder.LITTLE_ENDIAN);
						bb.put(fixupData[current+2]);
						bb.put(fixupData[current+3]);
						sourceOffset = bb.getShort(0);
						current += 4;
					}
					
					/*
					 * Fixup Record "Target data" (OBJNUM / TRGOFF)
					 */
					
					// Get target object number
					short objectNumber = 0;
					if (objectNumber16Bit) {
						ByteBuffer bb = ByteBuffer.allocate(2);
						bb.order(ByteOrder.LITTLE_ENDIAN);
						bb.put(fixupData[current]);
						bb.put(fixupData[current+1]);
						objectNumber = bb.getShort(0);
						current += 2;
					} else {
						objectNumber = fixupData[current];
						current++;
					}
					
					// Get target offset (i.e the target address to fix at the source)
					int targetOffset = 0;
					if ((targetFlags & 0x3) == 0) {
						if (is16bitSelectorFixup) {
							// no target offset present
						} else if (is32bitTargetOffset) {
							ByteBuffer bb = ByteBuffer.allocate(4);
							bb.order(ByteOrder.LITTLE_ENDIAN);
							bb.put(fixupData[current]);
							bb.put(fixupData[current+1]);
							bb.put(fixupData[current+2]);
							bb.put(fixupData[current+3]);
							
							targetOffset = bb.getInt(0);
							current += 4;
						} else {
							ByteBuffer bb = ByteBuffer.allocate(2);
							bb.order(ByteOrder.LITTLE_ENDIAN);
							bb.put(fixupData[current]);
							bb.put(fixupData[current+1]);
							targetOffset = bb.getShort(0);
							if (targetOffset < 0) {
								targetOffset += 0x10000;
							}
							current += 2;
						}
					}
					
					// not supported by dos32a anyway..
					if (isSourceList) {
						for (int k = 0; k < sourceCount; k++) {
							current += 2;
							// read sources..
						}
					}
					
					// Apply the actual fixup
					int base = getBaseAddress(le.getObjects().get(objectNumber-1));
					fixupsByType[sourceType & 0xf]++;
					if ((sourceType & 0xf) == LxFixupRecord.SOURCE_32BIT_OFFSET_FIXUP) {
						int value = base + targetOffset;
						if (logOffsets32bit) {
							Msg.debug(this, String.format(
								"32-bit offset fixup #%x at %08x (page %03x) -> %x (object #%x, target flags: %2x %s)",
								fixupCount, 
								getBaseAddress(object) + j*pageSize + sourceOffset,
								index,
								value, objectNumber,
								targetFlags, targetFlagsLabel
							));
							fixupCount++;
						}
						if (sourceOffset >= 0 && sourceOffset < pageData.length) {
							pageData[sourceOffset] = (byte)(value & 0xff);
						}
						if (sourceOffset+1 >= 0 && sourceOffset+1 < pageData.length) {
							pageData[sourceOffset+1] = (byte)((value & 0xff00)>>8);						
						}
						if (sourceOffset+2 >= 0 && sourceOffset+2 < pageData.length) {
							pageData[sourceOffset+2] = (byte)((value & 0xff0000)>>16);
						}
						if (sourceOffset+3 >= 0 && sourceOffset+3 < pageData.length) {
							pageData[sourceOffset+3] = (byte)((value & 0xff000000)>>24);
						}
						fixupsHandled++;
					} else if ((sourceType & 0xf) == LxFixupRecord.SOURCE_16BIT_OFFSET_FIXUP) {
						int value = base + targetOffset;
						if (logOffsets16bit) {
							Msg.debug(this, String.format(
								"16-bit offset fixup #%x at %08x (page %03x) -> %x (object #%x, target flags: %2x %s)",
								fixupCount, 
								getBaseAddress(object) + j*pageSize + sourceOffset,
								index,
								value, objectNumber,
								targetFlags, targetFlagsLabel
							));
							fixupCount++;
						}
						if (sourceOffset >= 0 && sourceOffset < pageData.length) {
							pageData[sourceOffset] = (byte)(value & 0xff);
						}
						if (sourceOffset+1 >= 0 && sourceOffset+1 < pageData.length) {
							pageData[sourceOffset+1] = (byte)((value & 0xff00)>>8);						
						}
						fixupsHandled++;
					} else if ((sourceType & 0xf) == LxFixupRecord.SOURCE_32BIT__SELF_REF_OFFSET_FIXUP) {
						int value = base + targetOffset;
						if (logSelfRel) {
							Msg.debug(this, String.format(
								"32-bit self-ref fixup #%x at %08x (page %03x) -> %x (object #%x, target flags: %2x %s)",
								fixupCount, 
								getBaseAddress(object) + j*pageSize + sourceOffset,
								index,
								value, objectNumber,
								targetFlags, targetFlagsLabel
							));
							fixupCount++;
						}
						long address = getBaseAddress(object) + j*pageSize + sourceOffset;
						value = (int) (value - address - 4);
						if (sourceOffset >= 0 && sourceOffset < pageData.length) {
							pageData[sourceOffset] = (byte)(value & 0xff);
						}
						if (sourceOffset+1 >= 0 && sourceOffset+1 < pageData.length) {
							pageData[sourceOffset+1] = (byte)((value & 0xff00)>>8);						
														}
						if (sourceOffset+2 >= 0 && sourceOffset+2 < pageData.length) {
							pageData[sourceOffset+2] = (byte)((value & 0xff0000)>>16);
						}
						if (sourceOffset+3 >= 0 && sourceOffset+3 < pageData.length) {
							pageData[sourceOffset+3] = (byte)((value & 0xff000000)>>24);
						}
						fixupsHandled++;
					} else if ((sourceType & 0xf) == LxFixupRecord.SOURCE_1616PTR_FIXUP) {
						if (log1616pointer) {
							Msg.debug(this, String.format(
								"16:16 pointer fixup #%x at %08x (page %03x) -> %02x:%04x (target flags: %2x %s) %2x %2x %2x %2x",
								fixupCount, 
								getBaseAddress(object) + j*pageSize + sourceOffset,
								index,
								base, targetOffset, objectNumber,
								targetFlags, targetFlagsLabel,
								pageData[sourceOffset],
								pageData[sourceOffset+1],
								pageData[sourceOffset+2],
								pageData[sourceOffset+3]
							));
							fixupCount++;
						}
						if (sourceOffset >= 0 && sourceOffset < pageData.length) {
							pageData[sourceOffset] = (byte)(base & 0xff);
						}
						if (sourceOffset+1 >= 0 && sourceOffset+1 < pageData.length) {
							pageData[sourceOffset+1] = (byte)((base & 0xff00)>>8);						
						}
						if (sourceOffset+2 >= 0 && sourceOffset+2 < pageData.length) {
							pageData[sourceOffset+2] = (byte)(targetOffset & 0xff);
						}
						if (sourceOffset+3 >= 0 && sourceOffset+3 < pageData.length) {
							pageData[sourceOffset+3] = (byte)((targetOffset & 0xff00)>>8);
						}
						fixupsHandled++;
					} else if ((sourceType & 0xf) == LxFixupRecord.SOURCE_16BIT_SELECTOR_FIXUP) {
						// 16 bit selector fixup
						fixupsHandled++;
					} else {
						Msg.warn(this, String.format(
							"WARNING: unhandled fixup #%x at %08x (type %02x, page %03x): %s -> object#%x:%x, target flags: %2x",
							fixupCount, 
							base + index * pageSize + sourceOffset,
							sourceType, index,
							isSourceList ? "source list " + sourceCount : String.format("%x", sourceOffset),
							objectNumber, targetOffset,
							targetFlags
						));
						fixupCount++;
						fixupsUnhandled++;
					}
				}
			}
			
			
			
			// Copy page into object block
			System.arraycopy(pageData, 0, block, (int) blockIndex, pageData.length);
			blockIndex += pageSize;
		}
		
		/*
		// Log fixup statistics
		ArrayList<String> byType = new ArrayList<>();
		String names[] = {
			"byte",
			"inv1",
			"sel16",
			"ptr16:16",
			"inv4",
			"off16",
			"ptr16:32",
			"off32",
			"off32self",
		};
		for (int i = 0; i < 9; i++) {
			if (fixupsByType[i] > 0) {
				byType.add(String.format("%s: %d", names[i], fixupsByType[i]));
			}
		}
		if (fixupsHandled + fixupsUnhandled > 0) {
			log.appendMsg(String.format(
				".object%d: %11s [%s]",
				object.number,
				String.format("%d fixups", fixupsHandled + fixupsUnhandled),
				
				String.join(", ", byType)
			));
		}
		*/
			
		return block;
	}
	
	private int getBaseAddress(ObjectTableEntry object) {
		int index = object.number - 1;
		if (baseAddresses != null && baseAddresses.length > index) {
			if (baseAddresses[index] != 0) {
				return baseAddresses[index];
			}
		}
		return object.base;
	}
	
	private int getSelector(ObjectTableEntry object) {
		int index = object.number - 1;
		if (selectors != null && selectors.length > index) {
			if (selectors[index] != 0) {
				return selectors[index];
			}
		}
		return index;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		var list = new ArrayList<Option>();
		list.add(new Option(GROUP_OVERRIDES, OPTION_BASE_ADDRESSES, ""));
		list.add(new Option(GROUP_OVERRIDES, OPTION_OBJECT_SELECTORS, ""));
		list.add(new Option(GROUP_LOGGING, OPTION_WARN_UNHANDLED_FIXUP, true));
		list.add(new Option(GROUP_LOGGING, OPTION_LOG_16BIT_OFFSET, false));
		list.add(new Option(GROUP_LOGGING, OPTION_LOG_32BIT_OFFSET, false));
		list.add(new Option(GROUP_LOGGING, OPTION_LOG_32BIT_SELFREL, false));
		list.add(new Option(GROUP_LOGGING, OPTION_LOG_1616_POINTER, false));
		list.add(new Option(GROUP_INIT, OPTION_DISASSEMBLE, true));
		list.add(new Option(GROUP_INIT, OPTION_OMIT_ENTRY, false));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		for (Option option : options) {
			if (option.getName().equals(OPTION_BASE_ADDRESSES)) {
				String value = option.getValue().toString();
				String[] addresses = value.split(",");
				baseAddresses = new int[addresses.length];
				for (int i = 0; i < addresses.length; i++) {
					String addr = addresses[i];
					addr = addr.replaceAll("0x", "");
					if (addr.length() > 0) {
						baseAddresses[i] = Integer.parseInt(addr, 16);	
					} else {
						baseAddresses[i] = 0;
					}
				}
			} else if (option.getName().equals(OPTION_OBJECT_SELECTORS)) {
				String value = option.getValue().toString();
				String[] values = value.split(",");
				selectors = new int[values.length];
				for (int i = 0; i < values.length; i++) {
					String v = values[i];
					v = v.replaceAll("0x", "");
					if (v.length() > 0) {
						selectors[i] = Integer.parseInt(v, 16);	
					} else {
						selectors[i] = 0;
					}
				}
			} else if (option.getName().equals(OPTION_OMIT_ENTRY)) {
				omitEntry = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_DISASSEMBLE)) {
				disassembleEntry = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_LOG_16BIT_OFFSET)) {
				logOffsets16bit = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_LOG_32BIT_OFFSET)) {
				logOffsets32bit = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_LOG_32BIT_SELFREL)) {
				logSelfRel = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_LOG_1616_POINTER)) {
				log1616pointer = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_WARN_UNHANDLED_FIXUP)) {
				warnUnhandled = Boolean.parseBoolean(option.getValue().toString());
			}
		}

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
