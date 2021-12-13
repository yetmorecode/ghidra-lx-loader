package yetmorecode.ghidra.format.lx;

import java.util.ArrayList;
import java.util.List;
import java.util.prefs.Preferences;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import yetmorecode.ghidra.format.lx.model.FixupRecord;
import yetmorecode.ghidra.format.lx.model.ObjectTableEntry;

public class LoaderOptions {
	public final static String GROUP_OVERRIDES = "Overrides";
	public final static String GROUP_FIXUPS = "Fixups";
	public final static String GROUP_MEMORY_MAPPING = "Memory";
	public final static String GROUP_IMAGE_MAPPING = "Image";
	
	public final static String OPTION_MAP_EXTRA = "Map LE Loader, Fixup & Data Sections";
	public final static String OPTION_PAGE_LABELS = "Create labels at page beginnings";
	public final static String OPTION_FIXUP_LABELS = "Create labels at fixup positions";
	
	
	public final static String OPTION_FIXUP_ENABLE_0 = "Apply byte fixups";
	public final static String OPTION_FIXUP_ENABLE_2 = "Apply 16-bit selector fixups";
	public final static String OPTION_FIXUP_ENABLE_3 = "Apply pointer 16:16 fixups";
	public final static String OPTION_FIXUP_ENABLE_5 = "Apply 16-bit offset fixups";
	public final static String OPTION_FIXUP_ENABLE_6 = "Apply pointer 16:32 fixups";
	public final static String OPTION_FIXUP_ENABLE_7 = "Apply 32-bit offset fixups";
	public final static String OPTION_FIXUP_ENABLE_8 = "Apply 32-bit offset self-ref fixups";
	public final static String OPTION_LOG_FIXUP_STATS = "Log fixup statistics";
	
	public final static String OPTION_OVERRIDE_ADDRESSES = "Object base addresses";
	public final static String OPTION_EMULATE_DOS32A = "Emulate DOS32A memory";
	public final static String OPTION_OVERRIDE_SELECTORS = "Object segment selectors";
	public final static String OPTION_ADD_ENTRY = "Mark entry point";
	public final static String OPTION_DISASSEMBLE = "Disassemble entry point";
	
	// Default options
	public boolean disassembleEntry = true;
	public boolean addEntry = true;
	public boolean mapExtra = true;
	public boolean[] enableType = new boolean[9];
	
	// More options available through "loader options"
	public boolean emulateDOS32A = false;
	public boolean logFixupStats = false;
	public boolean createPageLabels = false;
	public boolean createFixupLabels = false;
	public int[] baseAddresses;
	public int[] selectors;
	
	public LoaderOptions() {
		var prefs = Preferences.userRoot().node(this.getClass().getName());
		enableType[0] = prefs.getBoolean(OPTION_FIXUP_ENABLE_0, true);
		enableType[2] = prefs.getBoolean(OPTION_FIXUP_ENABLE_2, true);
		enableType[3] = prefs.getBoolean(OPTION_FIXUP_ENABLE_3, true);
		enableType[5] = prefs.getBoolean(OPTION_FIXUP_ENABLE_5, true);
		enableType[6] = prefs.getBoolean(OPTION_FIXUP_ENABLE_6, true);
		enableType[7] = prefs.getBoolean(OPTION_FIXUP_ENABLE_7, true);
		enableType[8] = prefs.getBoolean(OPTION_FIXUP_ENABLE_8, true);
		disassembleEntry = prefs.getBoolean(OPTION_DISASSEMBLE, disassembleEntry);
		addEntry = prefs.getBoolean(OPTION_ADD_ENTRY, addEntry);
		mapExtra = prefs.getBoolean(OPTION_MAP_EXTRA, mapExtra);
		emulateDOS32A = prefs.getBoolean(OPTION_EMULATE_DOS32A, emulateDOS32A);
		logFixupStats = prefs.getBoolean(OPTION_LOG_FIXUP_STATS, logFixupStats);
		createPageLabels = prefs.getBoolean(OPTION_PAGE_LABELS, createPageLabels);
		createFixupLabels = prefs.getBoolean(OPTION_FIXUP_LABELS, createFixupLabels);
		parseBaseAddresses(prefs.get(OPTION_OVERRIDE_ADDRESSES, ""));
		parseSelectors(prefs.get(OPTION_OVERRIDE_SELECTORS, ""));
	}
	
	public boolean fixupEnabled(FixupRecord r) {
		return enableType[r.getSourceType()];
	}
	
	public int getBaseAddress(ObjectTableEntry object) {
		var base = getBaseAddress(object.number);
		if (base > 0) {
			return base;
		}
		return object.base;
	}
	
	public int getBaseAddress(int number) {
		var index = number - 1;
		if (baseAddresses != null && baseAddresses.length > index) {
			if (baseAddresses[index] != 0) {
				return baseAddresses[index];
			}
		}
		return 0;
	}
	
	public int getSelector(ObjectTableEntry object) {
		return getSelector(object.number);
	}
	
	public int getSelector(int number) {
		var index = number - 1;
		if (selectors != null && selectors.length > index) {
			if (selectors[index] != 0) {
				return selectors[index];
			}
		}
		return index;
	}
	
	public int getSelector(short number) {
		var index = number - 1;
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
		
		var prefs = Preferences.userRoot().node(this.getClass().getName());
		
		list.add(new Option(GROUP_OVERRIDES, OPTION_ADD_ENTRY, prefs.getBoolean(OPTION_ADD_ENTRY, addEntry)));
		list.add(new Option(GROUP_OVERRIDES, OPTION_DISASSEMBLE, prefs.getBoolean(OPTION_DISASSEMBLE, disassembleEntry)));
		list.add(new Option(GROUP_OVERRIDES, OPTION_OVERRIDE_ADDRESSES, prefs.get(OPTION_OVERRIDE_ADDRESSES, "")));
		list.add(new Option(GROUP_OVERRIDES, OPTION_OVERRIDE_SELECTORS, prefs.get(OPTION_OVERRIDE_SELECTORS, "")));	
		
		//list.add(new Option(GROUP_OVERRIDES, OPTION_EMULATE_DOS32A, emulateDOS32A));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_MAP_EXTRA, prefs.getBoolean(OPTION_MAP_EXTRA, mapExtra)));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_PAGE_LABELS, prefs.getBoolean(OPTION_PAGE_LABELS, createPageLabels)));
		list.add(new Option(GROUP_IMAGE_MAPPING, OPTION_FIXUP_LABELS, prefs.getBoolean(OPTION_FIXUP_LABELS, createFixupLabels)));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_0, prefs.getBoolean(OPTION_FIXUP_ENABLE_0, enableType[0])));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_2, prefs.getBoolean(OPTION_FIXUP_ENABLE_2, enableType[2])));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_3, prefs.getBoolean(OPTION_FIXUP_ENABLE_3, enableType[3])));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_5, prefs.getBoolean(OPTION_FIXUP_ENABLE_5, enableType[5])));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_6, prefs.getBoolean(OPTION_FIXUP_ENABLE_6, enableType[6])));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_7, prefs.getBoolean(OPTION_FIXUP_ENABLE_7, enableType[7])));
		list.add(new Option(GROUP_FIXUPS, OPTION_FIXUP_ENABLE_8, prefs.getBoolean(OPTION_FIXUP_ENABLE_8, enableType[8])));
		list.add(new Option(GROUP_FIXUPS, OPTION_LOG_FIXUP_STATS, prefs.getBoolean(OPTION_LOG_FIXUP_STATS, logFixupStats)));
		return list;
	}
	
	public void validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		var prefs = Preferences.userRoot().node(this.getClass().getName());
		for (Option option : options) {
			if (option.getName().equals(OPTION_MAP_EXTRA)) {
				mapExtra = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_MAP_EXTRA, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_PAGE_LABELS)) {
				createPageLabels = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_PAGE_LABELS, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_LABELS)) {
				createFixupLabels = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_LABELS, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_ADD_ENTRY)) {
				addEntry = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_ADD_ENTRY, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_DISASSEMBLE)) {
				disassembleEntry = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_DISASSEMBLE, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_LOG_FIXUP_STATS)) {
				logFixupStats = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_LOG_FIXUP_STATS, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_0)) {
				enableType[0] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_0, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_2)) {
				enableType[2] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_2, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_3)) {
				enableType[3] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_3, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_5)) {
				enableType[5] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_5, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_6)) {
				enableType[6] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_6, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_7)) {
				enableType[7] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_7, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_FIXUP_ENABLE_8)) {
				enableType[8] = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_FIXUP_ENABLE_8, Boolean.parseBoolean(option.getValue().toString()));
			} else if (option.getName().equals(OPTION_EMULATE_DOS32A)) {
				emulateDOS32A = Boolean.parseBoolean(option.getValue().toString());
				prefs.putBoolean(OPTION_EMULATE_DOS32A, Boolean.parseBoolean(option.getValue().toString()));
			}
		}
		
		for (var option : options) {
			if (option.getName().equals(OPTION_OVERRIDE_ADDRESSES)) {
				String value = option.getValue().toString();
				prefs.put(OPTION_OVERRIDE_ADDRESSES, value);
				parseBaseAddresses(value);
			} else if (option.getName().equals(OPTION_OVERRIDE_SELECTORS)) {
				String value = option.getValue().toString();
				prefs.put(OPTION_OVERRIDE_SELECTORS, value);
				parseSelectors(value);
			}
		}
	}
	
	private void parseBaseAddresses(String value) {
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
	
	private void parseSelectors(String value) {
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
	}
}
