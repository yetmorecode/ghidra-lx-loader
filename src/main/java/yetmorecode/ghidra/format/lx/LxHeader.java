package yetmorecode.ghidra.format.lx;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.util.Conv;
import ghidra.util.Msg;
import yetmorecode.ghidra.format.lx.exception.InvalidHeaderException;

public class LxHeader extends yetmorecode.format.lx.LxHeader {
	
	public LxHeader(FactoryBundledWithBinaryReader reader, short index) throws IOException, InvalidHeaderException {
		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(Conv.shortToInt(index));

		signature = reader.readNextShort();
		if (signature != yetmorecode.format.lx.LxHeader.SIGNATURE_LE) {
			Msg.info("LE", String.format("wrong magic %x", signature));
			throw new InvalidHeaderException();
		}
		
		byteOrdering = reader.readNextByte();
		wordOrdering = reader.readNextByte();
		formatLevel = reader.readNextInt();
		cpuType = reader.readNextShort();
		osType = reader.readNextShort();
		moduleVersion = reader.readNextInt();
		moduleFlags = reader.readNextInt();
		
		pageCount = reader.readNextInt();
		eipObject = reader.readNextInt();
		eip = reader.readNextInt();
		espObject = reader.readNextInt();
		esp = reader.readNextInt();
		
		pageSize = reader.readNextInt();
		lastPageSize = reader.readNextInt();
		fixupSectionSize = reader.readNextInt();
		fixupSectionChecksum = reader.readNextInt();
		loaderSectionSize = reader.readNextInt();
		loaderSectionChecksum = reader.readNextInt();
		
		objectTableOffset = reader.readNextInt();
		objectCount = reader.readNextInt();
		pageTableOffset = reader.readNextInt();

		reader.setPointerIndex(index + 0x80);
		dataPagesOffset = reader.readNextInt();
		
		reader.setPointerIndex(oldIndex);
		
		fixupPageTableOffset = reader.readInt(index + 0x68);
		fixupRecordTableOffset =  reader.readInt(index + 0x6c);	
	}
}
