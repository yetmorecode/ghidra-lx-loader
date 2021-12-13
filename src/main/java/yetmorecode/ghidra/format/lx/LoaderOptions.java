package yetmorecode.ghidra.format.lx;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import yetmorecode.ghidra.format.lx.model.ObjectTableEntry;

public class LoaderOptions {
	public final static String GROUP_OVERRIDES = "Runtime overrides (comma-separated)";
	public final static String GROUP_LOGGING = "Logging";
	public final static String GROUP_MEMORY_MAPPING = "Memory";
	public final static String GROUP_IMAGE_MAPPING = "Image";
	
	public final static String OPTION_MAP_MZ = "Map MZ Header from EXE";
	public final static String OPTION_MAP_LX = "Map LX Header Section from EXE";
	public final static String OPTION_MAP_LOADER = "Map LE Loader Section from EXE";
	public final static String OPTION_MAP_FIXUP = "Map LE Fixup Section from EXE";
	public final static String OPTION_MAP_DATA = "Map LE Data Section from EXE";
	public final static String OPTION_PAGE_LABELS = "Create labels at page beginnings";
	public final static String OPTION_FIXUP_LABELS = "Create labels at fixup positions";
	
	public final static String OPTION_LOG_32BIT_OFFSET = "Log 32-bit offset fixups";
	public final static String OPTION_LOG_16BIT_OFFSET = "Log 16-bit offset fixups";
	public final static String OPTION_LOG_32BIT_SELFREL = "Log 32-bit self-rel fixups";
	public final static String OPTION_LOG_1616_POINTER = "Log 16:16 pointer fixups";
	public final static String OPTION_LOG_FIXUP_STATS = "Log fixup statistics";
	public final static String OPTION_BASE_ADDRESSES = "Object base addresses";
	public final static String OPTION_OBJECT_SELECTORS = "Object segment selectors";
	public final static String OPTION_OMIT_ENTRY = "Omit entry point";
	public final static String OPTION_DISASSEMBLE = "Disassemble from entry";
	
	// Default options
	public boolean disassembleEntry = true;
	public boolean mapMZ = true;
	public boolean mapLX = true;
	public boolean mapLoaderSection = true;
	
	// More options available through "loader options"
	public boolean logOffsets32bit = false;
	public boolean logOffsets16bit = false;
	public boolean logSelfRel = false;
	public boolean log1616pointer = false;
	public boolean logFixupStats = false;
	public boolean omitEntry = false;
	public boolean mapFixupSection = false;
	public boolean mapDataSection = false;
	public boolean createPageLabels = false;
	public boolean createFixupLabels = false;
	public int[] baseAddresses;
	public int[] selectors;
	
	public int getBaseAddress(ObjectTableEntry object) {
		int index = object.number - 1;
		if (baseAddresses != null && baseAddresses.length > index) {
			if (baseAddresses[index] != 0) {
				return baseAddresses[index];
			}
		}
		return object.base;
	}
	
	public int getSelector(ObjectTableEntry object) {
		int index = object.number - 1;
		if (selectors != null && selectors.length > index) {
			if (selectors[index] != 0) {
				return selectors[index];
			}
		}
		return index;
	}
	
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		var list = new ArrayList<Option>();
		list.add(new Option(GROUP_OVERRIDES, OPTION_BASE_ADDRESSES, ""));
		list.add(new Option(GROUP_OVERRIDES, OPTION_OBJECT_SELECTORS, ""));
		list.add(new Option(GROUP_LOGGING, OPTION_LOG_16BIT_OFFSET, logOffsets16bit));
		list.add(new Option(GROUP_LOGGING, OPTION_LOG_32BIT_OFFSET, logOffsets32bit));
		list.add(new Option(GROUP_LOGGING, OPTION_LOG_32BIT_SELFREL, logSelfRel));
		list.add(new Option(GROUP_LOGGING, OPTION_LOG_1616_POINTER, log1616pointer));
		list.add(new Option(GROUP_LOGGING, OPTION_LOG_FIXUP_STATS, logFixupStats));
		list.add(new Option(GROUP_MEMORY_MAPPING, OPTION_DISASSEMBLE, disassembleEntry));
		list.add(new Option(GROUP_MEMORY_MAPPING, OPTION_OMIT_ENTRY, omitEntry));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_MAP_MZ, mapMZ));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_MAP_LX, mapLX));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_MAP_LOADER, mapLoaderSection));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_MAP_FIXUP, mapFixupSection));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_MAP_DATA, mapDataSection));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_PAGE_LABELS, createPageLabels));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_FIXUP_LABELS, createFixupLabels));
		return list;
	}
	
	public void validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
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
			} else if (option.getName().equals(OPTION_MAP_MZ)) {
				mapMZ = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_MAP_LX)) {
				mapLX = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_MAP_DATA)) {
				mapDataSection = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_MAP_LOADER)) {
				mapLoaderSection = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_PAGE_LABELS)) {
				createPageLabels = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_FIXUP_LABELS)) {
				createFixupLabels = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_MAP_FIXUP)) {
				mapFixupSection = Boolean.parseBoolean(option.getValue().toString());
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
			} else if (option.getName().equals(OPTION_LOG_FIXUP_STATS)) {
				logFixupStats = Boolean.parseBoolean(option.getValue().toString());
			} else if (option.getName().equals(OPTION_LOG_1616_POINTER)) {
				log1616pointer = Boolean.parseBoolean(option.getValue().toString());
			}
		}
	}
}
