package yetmorecode.ghidra.loader.lx;

import java.util.ArrayList;
import java.util.Collection;

import yetmorecode.ghidra.format.lx.ObjectMapEntry;

public class LxLoaderOptions {

	private boolean useDos32A = false;
	private int memoryBaseDos32A = 0x170000;
	
	private boolean useDos4GW = false;
	
	private Collection selectors;
	private Collection baseAddresses;
	
	public boolean isDos32A() {
		return useDos32A;
	}
	
	public boolean isDos4GW() {
		return useDos4GW;
	}
	
	public boolean isDefault() {
		return !isDos32A() && !isDos4GW();
	}
	
	public int getBaseAddress(int objectNumber, ObjectMapEntry[] objects) {
		int base = objects[objectNumber-1].base;
		if (isDos32A()) {
			// Dos32A just allocates all objects one after another 
			// with a 16 byte control block (supposedly for memory management)
			// in between.
			base = memoryBaseDos32A;
			for (int i = 0; i < objectNumber - 2; i++) {
				// 16 byte memory management block
				base += 0x10;
				// actual object data
				base += Math.ceil(objects[i].size / 0x10) * 0x10;
			}
		} else if (isDos4GW()) {
		
		}
		return base;
	}
	
}
