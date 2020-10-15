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

	@Override
	public String getName() {
		return "Old MS-DOS style 32bit Linear Executable (LE/LX)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (provider.length() < 4) {
			return loadSpecs;
		}
		try {
			LxExecutable executable = new LxExecutable(RethrowContinuesFactory.INSTANCE, provider);
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("x86:LE:32:default", "borlandcpp"), true));
			//loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("x86:LE:32:default", "gcc"), true));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidHeaderException e) {
			// Everything is ok, but the provided data is not a valid LX/LE header
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
		monitor.setMessage("Processing LE executable...");
		
		ContinuesFactory factory = MessageLogContinuesFactory.create(log);

		// We don't use the file bytes to create block because the bytes are manipulated before
		// forming the block.  Creating the FileBytes anyway in case later we want access to all
		// the original bytes.
		MemoryBlockUtils.createFileBytes(program, provider, monitor);
		
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		LxExecutable le;
		try {
			le = new LxExecutable(factory, provider);
			LxHeader ib = le.getLeHeader();
			/*
			log.appendMsg(String.format("number of objects: %x", ib.getObjectCount()));
			log.appendMsg(String.format("bytes on last page: %x", ib.getBytesOnLastPage()));
			log.appendMsg(String.format("size: --, initial eip: %x", ib.getInitialEIP()));
			log.appendMsg(String.format("object table offset: %x", ib.getObjectTableOffset()));
			log.appendMsg(String.format("object page map offset: %x", ib.getObjectPageMapOffset()));
			log.appendMsg(String.format("fixup page table offset: %x", ib.getFixupPageTableOffset()));
			log.appendMsg(String.format("fixup record table offset: %x", ib.getFixupRecordTableOffset()));
			log.appendMsg(String.format("data page offset size: %x", ib.getDataPagesOffset()));
			log.appendMsg(String.format("data page offset size: %x", ib.getDataPagesOffset()));
			*/
			long pageSize = ib.pageSize; 
			
			int i = 0;
			for (ObjectMapEntry object : le.getObjects()) {
				log.appendMsg("Object #" + (i++), String.format(
					"base: %x - %x (%x), pages: %x (%x)", 
					object.base, 
					object.base + object.size,
					object.size,
					object.pageCount, 
					object.pageTableIndex
				));
			}
			
			// Map each object
			i = 0;
			for (ObjectMapEntry object : le.getObjects()) {
				
				// Temporary memory to assemble all pages to one block
				byte block[] = new byte[object.size+4096];
				long blockIndex = 0;
				
				// Loop through all pages for this object and add them together
				long pageMapOffset = le.getDosHeader().e_lfanew() + ib.pageTableOffset;
				long fixupPageMapOffset = le.getDosHeader().e_lfanew() + ib.fixupPageTableOffset;
				long fixupRecordOffset = le.getDosHeader().e_lfanew() + ib.fixupRecordTableOffset;
				for (int j = 0; j < object.pageCount; j++) {
					// Page map indices are one-based, so subtract one 
					long index = object.pageTableIndex + j - 1;
					
					PageMapEntry entry = new PageMapEntry(le.getReader(), (int) (pageMapOffset + index*4));
					
					int fixupBegin = le.getReader().readInt(fixupPageMapOffset + index*4);
					int fixupEnd = le.getReader().readInt(fixupPageMapOffset + index*4 + 4);
					
					long pageOffset  = ib.dataPagesOffset + (entry.getIndex()-1)*pageSize;
					/*
					log.appendMsg(String.format(
						"page %x/%x: page offset: %x fixups: %x - %x / %x", 
						index, entry.getIndex(), 
						pageOffset,
						fixupBegin, fixupEnd, fixupEnd - fixupBegin
					));
					*/
					
					// Read page from file
					FactoryBundledWithBinaryReader r = le.getReader();
					r.setPointerIndex(pageOffset);
					byte[] pageData = r.readNextByteArray((int) pageSize);
					
					// Apply fixups to page
					int fixupDataSize = fixupEnd - fixupBegin;
					int fixupCount = 0;
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
							
							// only 3rd page fixups for debug
							if (index == 0x13 && targetOffset < 0) {
								log.appendMsg(String.format(
									" fix%x: %s, %x:%x(%d)%x+%x=%x => %s %s",
									fixupCount, 
									"", objectNumber, targetOffset, targetOffset,
									getBaseAddress(le.getObjects()[objectNumber-1]), targetOffset, getBaseAddress(le.getObjects()[objectNumber-1]) + targetOffset,  
									"", 
									isSourceList ? "source list " + sourceCount : String.format("off: %x", sourceOffset)
								));
							}
							
							if ((sourceType & 0xf) == 7 && sourceOffset > 0 && sourceOffset < pageData.length - 4) {
								int base = getBaseAddress(le.getObjects()[objectNumber-1]);
								int value = base + targetOffset;
								pageData[sourceOffset] = (byte)(value & 0xff);
								pageData[sourceOffset+1] = (byte)((value & 0xff00)>>8);
								pageData[sourceOffset+2] = (byte)((value & 0xff0000)>>16);
								pageData[sourceOffset+3] = (byte)((value & 0xff000000)>>24);
							} else {
								log.appendMsg(String.format(
									" unhandled fixup %x:%x: %s, %x:%x => %s(%x) %s",
									index, fixupCount, 
									"", objectNumber, targetOffset,
									"", sourceType, 
									isSourceList ? "source list " + sourceCount : String.format("src offset: %x", sourceOffset)
								));
							}
							
							fixupCount++;
						}
					}
					
					// Copy page into object block
					System.arraycopy(pageData, 0, block, (int) blockIndex, pageData.length);
					blockIndex += pageSize;
				}
				
				program.getMemory().createInitializedBlock(
					"object" + object.number, 
					space.getAddress(getBaseAddress(object)), 
					new ByteArrayInputStream(block), 
					object.size, 
					monitor, false
				);
				i++;
				
			}
			
			FlatProgramAPI api = new FlatProgramAPI(program, monitor);
			int eip = le.getLeHeader().eip;
			eip += 0x170010;
			api.addEntryPoint(api.toAddr(eip));
			//api.disassemble(api.toAddr(eip));
			//api.createFunction(api.toAddr(eip), "_entry");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
	}
	
	private int getBaseAddress(ObjectMapEntry object) {
		switch (object.number) {
		case 1:
			return 0x170010;
		case 2:
			return 0x2c59c0;
		case 3:
			return 0x2c59e0;
		default:
			return object.base;
		}
		
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		list.add(new Option("guess_dos32a", "1"));
		list.add(new Option("dos32a_base_adress", "0x170000"));
		list.add(new Option("dos32a_selectors", "828,838,838"));
		list.add(new Option("guess_dos4gw", "1"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
