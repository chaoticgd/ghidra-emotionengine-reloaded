package ghidra.emotionengine.dvp;

import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.emotionengine.EE_ElfSection;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.task.TaskMonitor;

// Emitted by: https://github.com/GirianSeed/ee-gcc/blob/2.9-ee-991111-01/gas/config/tc-dvp.c#L2453-L2584

public final class DvpOverlayTable implements EE_ElfSection {

	private static final String DVP_EXT_OVERLAY_NAME = "Elf32_Dvp_External_Overlay";
	public static final String SHNAME_DVP_OVERLAY_TABLE = ".DVP.ovlytab";
	private static final long VU1_TEXT_ADDRESS = 0x11008000;
	private static final long VU1_DATA_ADDRESS = 0x1100C000;

	private final ElfSectionHeader header;
	private final ElfLoadHelper elf;

	public DvpOverlayTable(ElfSectionHeader header, ElfLoadHelper elf) {
		this.header = header;
		this.elf = elf;
	}

	private Structure getDvpExtOverlay() {
		Structure struct =
			new StructureDataType(ELF_PATH, DVP_EXT_OVERLAY_NAME, 0);
		struct.add(ElfHeader.DWORD, "name", null);
		struct.add(ElfHeader.DWORD, "lma", null);
		struct.add(ElfHeader.DWORD, "vma", null);
		return struct;
	}

	@Override
	public void parse(TaskMonitor monitor) throws Exception {
		Memory mem = elf.getProgram().getMemory();
		ElfHeader elfHeader = elf.getElfHeader();
		Structure struct = getDvpExtOverlay();
		long headerSize = header.getSize();
		if (headerSize == 0) {
			// only 1 function
			ElfSectionHeader section = elfHeader.getSection(".vutext");
			if (section != null) {
				parseVuSection(elf, section);
			}
			section = elfHeader.getSection(".vudata");
			if (section != null) {
				parseVuSection(elf, section);
			}
			return;
		}
		int arraySize = (int) headerSize / struct.getLength();
		Array array = new ArrayDataType(struct, arraySize, struct.getLength());
		Data data = elf.createData(elf.findLoadAddress(header, 0), array);
		DvpOverlayStringTable strTab = new DvpOverlayStringTable(elf);
		for (int i = 0; i < data.getNumComponents(); i++) {
			monitor.checkCancelled();
			Data comp = data.getComponent(i);
			Scalar scalar = (Scalar) comp.getComponent(0).getValue();
			long overlayNameOffset = scalar.getValue();
			String shName = null;
			try {
				Address nameAddr = elf.getDefaultAddress(overlayNameOffset);
				shName = strTab.getString(nameAddr);
				if (shName.equals("")) {
					continue;
				}
				ElfSectionHeader section = elfHeader.getSection(shName);
				long base = section.isExecutable() ? VU1_TEXT_ADDRESS : VU1_DATA_ADDRESS;
				MemoryBlock block = mem.getBlock(shName);
				if (block != null) {
					mem.removeBlock(block, monitor);
				}
				scalar = (Scalar) comp.getComponent(2).getValue();
				long vmaValue = scalar.getValue();
				Address addr = elf.getDefaultAddress(vmaValue + base);
				
				// Rename sections with new format: .DVP.overlay..<overlay_name_offset>.<filename_hash>.<vaddr>.<line_of_split>.<counter>
				// Extract components from the original section name
				String blockName = shName;
				if (shName.startsWith(".DVP.overlay..")) {
					// Parse the original format to extract components
					String[] parts = shName.substring(".DVP.overlay..".length()).split("\\.");
					if (parts.length >= 4) {
						// parts[0] = old vaddr (or "unknvma") - discarded
						// parts[1] = filename_hash
						// parts[2] = line_of_split
						// parts[3] = counter
						String filenameHash = parts[1];
						String lineOfSplit = parts[2];
						String counter = parts[3];
						
						// Format with proper padding:
						// overlay_name_offset: 4 hex chars (e.g., "0x0000")
						// vaddr: 4 hex chars (e.g., "0x0000")
						// line_of_split: 4 decimal chars (e.g., "0000")
						blockName = String.format(".DVP.overlay..0x%04x.%s.0x%04x.%04d.%s",
							overlayNameOffset,
							filenameHash,
							vmaValue,
							Integer.parseInt(lineOfSplit),
							counter);
						
						elf.getLog().appendMsg(String.format(
							"Renamed section '%s' to '%s' (overlay_name_offset: 0x%04x, VMA: 0x%04x)",
							shName, blockName, overlayNameOffset & 0xFF, vmaValue & 0xFFFF));
					}
				}
				
				scalar = (Scalar) comp.getComponent(1).getValue();
				Address mappedAddress = elf.getDefaultAddress(scalar.getValue());
				block = mem.createByteMappedBlock(
					blockName, addr, mappedAddress, (int) section.getLogicalSize(), true);
				// TODO: Restore VU instructions in Sleigh files so we can enable this
				// if (section.isExecutable()) {
				// 	EmotionEngineLoader.setMicroMode(elf.getProgram(), block);
				// 	elf.createOneByteFunction(null, block.getStart(), true);
				// 	block.setExecute(true);
				// }
				block.setRead(true);
				block.setWrite(section.isWritable());
			}
			catch (Exception e) {
				elf.getLog().appendException(e);
			}
		}
	}

	private void parseVuSection(ElfLoadHelper elfLoadHelper, ElfSectionHeader section) {
		Program program = elfLoadHelper.getProgram();
		Memory mem = program.getMemory();
		long base = section.isExecutable() ? VU1_TEXT_ADDRESS : VU1_DATA_ADDRESS;
		Address sectionAddress = elfLoadHelper.getDefaultAddress(section.getAddress());
		Address addr = elfLoadHelper.getDefaultAddress(base);
		String sectionName = section.getNameAsString();
		MemoryBlock origBlock = mem.getBlock(sectionAddress);
		try {
			MemoryBlock block = mem.createByteMappedBlock(
				sectionName + "_overlay", addr, sectionAddress, (int) origBlock.getSize(), true);
			byte[] bytes = new byte[(int) section.getLogicalSize()];
			MemoryBufferImpl buf = new MemoryBufferImpl(mem, sectionAddress);
			buf.getBytes(bytes, 0);
			if (bytes.length > 0) {
				block.putBytes(block.getStart(), bytes);
			}
			block.setRead(origBlock.isRead());
			block.setWrite(origBlock.isWrite());
			block.setExecute(origBlock.isExecute());
			block.setVolatile(origBlock.isVolatile());
			// TODO: Restore VU instructions in Sleigh files so we can enable this
			// if (section.isExecutable()) {
			// 	EmotionEngineLoader.setMicroMode(program, block);
			// 	elfLoadHelper.createOneByteFunction(null, block.getStart(), true);
			// }
		} catch (Exception e) {
			elfLoadHelper.getLog().appendException(e);
		}
	}
}
