package ghidra.emotionengine;

import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.extend.MIPS_ElfExtension;
import ghidra.emotionengine.dvp.DvpOverlayTable;
// import ghidra.emotionengine.iop.IopModSection;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.classfinder.ExtensionPointProperties;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@ExtensionPointProperties(priority = 2)
public class EE_ElfExtension extends MIPS_ElfExtension {

	public static final short ET_IRX = -128;
	public static final short ET_IRX2 = -127;
	public static final short ET_ERX2 = -111;

	public static final int E_MIPS_MACH_5900 = 0x00920000;

	// Program Headers
	public static final ElfProgramHeaderType PT_MIPS_IRXHDR = new ElfProgramHeaderType(0x70000080, "PT_MIPS_IRXHDR",
			"IRX header");

	private static final int SHT_MIPS_IOPMOD_VALUE = 0x70000080;
	private static final int SHT_DVP_OVERLAY_TABLE_VALUE = 0x7ffff420;

	// Sections Headers
	public static final ElfSectionHeaderType SHT_MIPS_IOPMOD = new ElfSectionHeaderType(SHT_MIPS_IOPMOD_VALUE,
			"SHT_MIPS_IOPMOD", "IOP Module Information");
	public static final ElfSectionHeaderType SHT_DVP_OVERLAY_TABLE = new ElfSectionHeaderType(
			SHT_DVP_OVERLAY_TABLE_VALUE, "SHT_DVP_OVERLAY_TABLE", "The VU overlay table");
	public static final ElfSectionHeaderType SHT_DVP_OVERLAY = new ElfSectionHeaderType(0x7ffff421, "SHT_DVP_OVERLAY",
			"A VU overlay");

	// OUT OF RANGE?
	// public static final ElfSectionHeaderType SHT_MW_CATS = new
	// ElfSectionHeaderType(
	// 0xca2a82c2, "SHT_MW_CATS", "Unknown Section from Metrowerks CATS Utility");

	public static final String SHNAME_DVP_OVERLAY_STRTAB = ".DVP.ovlystrtab";
	public static final String SHNAME_DVP_OVERLAY_TABLE = ".DVP.ovlytab";

	// DVP Values
	/* These values are used for the dvp. */
	public static final byte STO_DVP_DMA = (byte) 0xe8;
	public static final byte STO_DVP_VIF = (byte) 0xe9;
	public static final byte STO_DVP_GIF = (byte) 0xea;
	public static final byte STO_DVP_VU = (byte) 0xeb;
	/* Reserve a couple in case we need them. */
	public static final byte STO_DVP_RES1 = (byte) 0xec;
	public static final byte STO_DVP_RES2 = (byte) 0xed;

	@Override
	public String getDataTypeSuffix() {
		return "_EE";
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		return EE_Util.isEmotionEngine(elfLoadHelper.getProgram());
	}

	@Override
	public void processElf(ElfLoadHelper helper, TaskMonitor monitor) throws CancelledException {

		super.processElf(helper, monitor);
		ElfHeader elf = helper.getElfHeader();
		try {
			createMirrorBlocks(helper);
		} catch (Exception e) {
			helper.log(e);
		}
		for (ElfSectionHeader shdr : elf.getSections()) {
			monitor.checkCancelled();
			EE_ElfSection section;
			switch (shdr.getType()) {
			// TODO: Integrate from bigianb fork
			// case SHT_MIPS_IOPMOD_VALUE:
			// 	section = new IopModSection(shdr, helper);
			// 	break;
			case SHT_DVP_OVERLAY_TABLE_VALUE:
				section = new DvpOverlayTable(shdr, helper);
				break;
			default:
				section = null;
				break;
			}
			try {
				if (section == null) {
					String name = shdr.getNameAsString();
					if (name != null) {
						if (name.equals("heap") && shdr.getSize() == 0) {
							createHeapSection(helper, shdr);
						}
					}
				} else {
					section.parse(monitor);
				}
			} catch (Exception e) {
				helper.log(e);
			}
		}
	}

	private void createHeapSection(ElfLoadHelper helper, ElfSectionHeader shdr) throws Exception {
		Program program = helper.getProgram();
		List<Symbol> symbols = program.getSymbolTable().getSymbols("_gp", program.getGlobalNamespace());
		if (symbols.isEmpty()) {
			return;
		}
		Address end = helper.getDefaultAddress(shdr.getAddress());
		Address start = getMaxAddress(helper);
		long size = end.subtract(start) + 1;
		Memory mem = program.getMemory();
		MemoryBlock block = mem.createUninitializedBlock("heap", start, size, false);
		block.setExecute(shdr.isExecutable());
		block.setRead(true);
		block.setWrite(true);
		ProgramModule root = program.getListing().getDefaultRootModule();
		if (root.getIndex("heap") == -1) {
			ProgramFragment frag = root.createFragment("heap");
			frag.move(start, end);
		}
	}

	private Address getMaxAddress(ElfLoadHelper helper) {
		Program program = helper.getProgram();
		return Arrays.stream(program.getMemory().getBlocks()).filter(MemoryBlock::isLoaded)
				.filter(MemoryBlock::isInitialized).map(MemoryBlock::getEnd).map(Address::next).max(Address::compareTo)
				.orElse(null);
	}

	private static void createMirrorBlocks(ElfLoadHelper helper) throws Exception {
		// start end bytes description
		// 0x00000000 - 0x01E84800 32000000 (main ram cached)
		// 0x20000000 - 0x21E84800 32000000 (main ram uncached)
		// 0x30100000 - 0x31E905C0 31000000 (main ram uncached & accelerated)
		// 0x1C000000 - 0x1E000000 02000000 (iop ram)
		// 0x1FC00000 - 0x1FFD0900 04000000 (BIOS/rom0 uncached)
		// 0x9FC00000 - 0x9FFD0900 04000000 (BIOS/rom09 cached)
		// 0xBFC00000 - 0xBFFD0900 04000000 (BIOS/rom0b uncached)
		//
		//
		// KUSEG: 00000000h-7FFFFFFFh User segment
		// KSEG0: 80000000h-9FFFFFFFh Kernel segment 0
		// KSEG1: A0000000h-BFFFFFFFh Kernel segment 1
		//
		// Physical
		// 00000000h 2 MB Main RAM (same as on PSX)
		// 1D000000h SIF registers
		// 1F800000h 64 KB Various I/O registers
		// 1F900000h 1 KB SPU2 registers
		// 1FC00000h 4 MB BIOS (rom0) - Same as EE BIOS
		//
		// FFFE0000h (KSEG2) Cache control
		Program program = helper.getProgram();
		Memory mem = program.getMemory();
		Address ram = helper.getDefaultAddress(0);
		Address start = helper.getDefaultAddress(0x20000000);
		mem.createByteMappedBlock("RAM(uncached)", start, ram, 32000000, false);
		start = helper.getDefaultAddress(0x30100000);
		mem.createByteMappedBlock("RAM(uncached_and_accelerated)", start, ram, 32000000, false);
		ram = helper.getDefaultAddress(0x1FC00000);
		start = helper.getDefaultAddress(0x9FC00000);
		mem.createByteMappedBlock("BIOS/rom09(cached)", start, ram, 04000000, false);
		start = helper.getDefaultAddress(0xBFC00000);
		mem.createByteMappedBlock("BIOS/rom0b(uncached)", start, ram, 04000000, false);
	}
}
