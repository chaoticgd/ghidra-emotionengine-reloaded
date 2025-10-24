package ghidra.emotionengine.dvp;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.program.model.address.Address;

public class DvpOverlayStringTable {

	public static final String SHNAME_DVP_OVERLAY_STRTAB = ".DVP.ovlystrtab";

	private final BinaryReader reader;
	private final long offset;
	private final Address address;

	DvpOverlayStringTable(ElfLoadHelper elf) {
		ElfHeader header = elf.getElfHeader();
		ElfSectionHeader strTab = header.getSection(SHNAME_DVP_OVERLAY_STRTAB);
		this.reader = strTab.getReader();
		this.offset = strTab.getOffset();
		this.address = elf.getDefaultAddress(strTab.getAddress());
	}

	String getString(Address addr) throws IOException {
		long index =  offset + addr.subtract(address);
		return reader.readAsciiString(index);
	}
}
