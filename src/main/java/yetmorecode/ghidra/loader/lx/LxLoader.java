package yetmorecode.ghidra.loader.lx;

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
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import yetmorecode.ghidra.format.lx.LxExecutable;
import yetmorecode.ghidra.format.lx.LxHeader;
import yetmorecode.ghidra.format.lx.ObjectMapEntry;
import yetmorecode.ghidra.format.lx.PageMapEntry;
import yetmorecode.ghidra.format.lx.exception.InvalidHeaderException;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class LxLoader extends AbstractLibrarySupportLoader {

	private final static String OPTION_BASE_ADDRESSES = "Override object base addresses (comma-seperated)";
	
	private MessageLog log;
	private int[] baseAddresses;
	
	@Override
	public String getName() {
		return "Linear Executable (LE/LX)";
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
			// Everything is ok, but the provided data is not a valid LX/LE header
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

		MemoryBlockUtils.createFileBytes(program, provider, monitor);		
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		LxExecutable executable;
		try {
			executable = new LxExecutable(factory, provider);
			LxHeader header = executable.getLeHeader();
			log.appendMsg(String.format("Number of objects: %x", header.objectCount));
			
			for (ObjectMapEntry object : executable.getObjects()) {
				log.appendMsg(String.format(
					"Object #%x base: %08x - %08x (%06x), pages: %03x - %03x (%x)",
					object.number,
					object.base, object.base + object.size, object.size,
					object.pageTableIndex, object.pageTableIndex + object.pageCount - 1, object.pageCount 
				));
			}
			
			// Map each object
			for (ObjectMapEntry object : executable.getObjects()) {
				byte[] block = createObjectBlock(executable, object, object.number == executable.getObjects().size());
				program.getMemory().createInitializedBlock(
					"object" + object.number, 
					space.getAddress(getBaseAddress(object)), 
					new ByteArrayInputStream(block), 
					object.size, 
					monitor, false
				);
			}
			
			FlatProgramAPI api = new FlatProgramAPI(program, monitor);
			int eip = executable.getLeHeader().eip;
			var o = executable.getObjects().get(executable.getLeHeader().eipObject-1);
			eip += getBaseAddress(o);			
			log.appendMsg(String.format("Entrypoint set at %08x (%08x + %08x)", eip, getBaseAddress(o), executable.getLeHeader().eip));
			api.addEntryPoint(api.toAddr(eip));
			api.disassemble(api.toAddr(eip));
			api.createFunction(api.toAddr(eip), "_entry");
		} catch (Exception e) {
			e.printStackTrace();
		}	
	}
	
	private byte[] createObjectBlock(LxExecutable le, ObjectMapEntry object, boolean isLastObject) throws IOException {
		// Temporary memory to assemble all pages to one block
		byte block[] = new byte[object.size+4096];
		long blockIndex = 0;
		
		// Loop through all pages for this object and add them together
		LxHeader ib = le.getLeHeader();
		long pageMapOffset = le.getDosHeader().e_lfanew() + ib.pageTableOffset;
		long fixupPageMapOffset = le.getDosHeader().e_lfanew() + ib.fixupPageTableOffset;
		long fixupRecordOffset = le.getDosHeader().e_lfanew() + ib.fixupRecordTableOffset;
		long pageSize = ib.pageSize; 
		
		int unhandled = 0;
		log.appendMsg(String.format("Mapping object #%x to memory location %08x - %08x", 
				object.number, 
				getBaseAddress(object),
				getBaseAddress(object) + object.size
		));
		
		for (int j = 0; j < object.pageCount; j++) {
			// Page map indices are one-based, so subtract one 
			long index = object.pageTableIndex + j - 1;
			
			PageMapEntry entry = new PageMapEntry(le.getReader(), (int) (pageMapOffset + index*4));
			
			int fixupBegin = le.getReader().readInt(fixupPageMapOffset + index*4);
			int fixupEnd = le.getReader().readInt(fixupPageMapOffset + index*4 + 4);					
			long pageOffset  = ib.dataPagesOffset + (entry.getIndex()-1)*pageSize;

			
			// Read page from file
			FactoryBundledWithBinaryReader r = le.getReader();
			r.setPointerIndex(pageOffset);
			byte[] pageData;
			var isLastPage = j == object.pageCount - 1;
			if (isLastObject && isLastPage) {
				pageData = r.readNextByteArray(ib.lastPageSize);
			} else {
				pageData = r.readNextByteArray((int) pageSize);	
			}
			
			// Apply fixups to page
			int fixupDataSize = fixupEnd - fixupBegin;
			if (fixupDataSize > 0) {
				byte fixupData[] = le.getReader().readByteArray(fixupRecordOffset + fixupBegin, fixupDataSize);
				
				int current = 0;
				while (current < fixupDataSize) {
					byte sourceType = fixupData[current];
					byte targetFlags = fixupData[current+1];
					boolean isSourceList = (sourceType & 0x20) > 0;
					boolean is16bitSelectorFixup = (sourceType & 0xf) == 2;
					boolean is32bitTargetOffset = false;
					boolean objectNumber16Bit = false;
					if ((targetFlags & 0x10) > 0) {
						is32bitTargetOffset = true;
						//targetFlagsLabel += " 32-bit target offset,";
					}
					if ((targetFlags & 0x40) > 0) {
						objectNumber16Bit = true;
						//targetFlagsLabel += " 16-bit object number,";
					}
					
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
					
					short objectNumber = 0;
					// Target data

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
					
					if ((sourceType & 0xf) == 7) {
						int base = getBaseAddress(le.getObjects().get(objectNumber-1));
						int value = base + targetOffset;								
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
					} else if ((sourceType & 0xf) == 2) {
						// 16 bit selector fixup
					} else {
						log.appendMsg(String.format(
							"WARNING: unhandled fixup #%x at %08x (type %x, page %03x): %s -> object#%x:%x",
							unhandled, 
							getBaseAddress(object) + index * pageSize + sourceOffset,
							sourceType, index,
							isSourceList ? "source list " + sourceCount : String.format("%x", sourceOffset),
							objectNumber, targetOffset
						));
						unhandled++;
					}
				}
			}
			
			// Copy page into object block
			System.arraycopy(pageData, 0, block, (int) blockIndex, pageData.length);
			blockIndex += pageSize;
		}
		
		return block;
	}
	
	private int getBaseAddress(ObjectMapEntry object) {
		int index = object.number - 1;
		if (baseAddresses != null && baseAddresses.length > index) {
			if (baseAddresses[index] != 0) {
				return baseAddresses[index];
			}
		}
		return object.base;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		var list = new ArrayList<Option>();
		list.add(new Option(OPTION_BASE_ADDRESSES, ""));
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
			}
		}

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
