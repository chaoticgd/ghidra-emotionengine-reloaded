/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.emotionengine.relocation;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.relocation.ElfRelocationContext;
import ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationConstants;
import ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.util.classfinder.ExtensionPointProperties;
import ghidra.util.exception.NotFoundException;

@ExtensionPointProperties(priority = 2)
public class EmotionEngine_ElfRelocationHandler extends MIPS_ElfRelocationHandler {

	private static final int R_MIPS_MHI16 = 0xfa;
	private static final int R_MIPS_ADDEND = 0xfb;
	private static final int R_MIPS15_S3 = 119;
	private static final int R_MIPS_DVP_11_PCREL = 120;
	private static final int R_MIPS_DVP_27_S4 = 121;
	private static final int R_MIPS_DVP_11_S4 = 122;
	private static final int R_MIPS_DVP_U15_S3 = 123;
	private static final String ILLEGAL_RELOCATION_MESSAGE =
		"Illegal R_MIPS_MHI16 Relocation in ET_IRX2 IopModule";
	private static final String ILLEGAL_MHI16_MESSAGE =
		"R_MIPS_MHI16 not followed by R_MIPS_ADDEND";

	private static final int LOW_MASK = 0xffff;
	private static final int HIGH_MASK = 0xffff0000;
	private static final int DVP_MASK = 0x7FFFFFF0;
	
	public static final short ET_IRX2 = -127;
	public static final int E_MIPS_MACH_5900 = 0x00920000;

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return super.canRelocate(elf) && ((elf.e_flags() & E_MIPS_MACH_5900) == E_MIPS_MACH_5900);
	}

	@Override
	public RelocationResult relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException {
		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();
		MessageLog log = elfRelocationContext.getLog();
		BookmarkManager bMan = program.getBookmarkManager();
		ElfSymbol elfSymbol = elfRelocationContext.getSymbol(relocation.getSymbolIndex());

		String symbolName = elfSymbol.getNameAsString();

		int base = (int) elfRelocationContext.getImageBaseWordAdjustmentOffset();
		int value = 0;
		int newValue = 0;
		int oldValue = memory.getInt(relocationAddress);
		switch(relocation.getType()) {
			case MIPS_ElfRelocationConstants.R_MIPS_16:
				value = (oldValue << 16) >> 16;
				value += base;
				newValue = oldValue & HIGH_MASK;
				newValue |= value & LOW_MASK;
				break;
			case MIPS_ElfRelocationConstants.R_MIPS_32:
				newValue = oldValue+base;
				break;
			case MIPS_ElfRelocationConstants.R_MIPS_26:
				value = (oldValue & MIPS_ElfRelocationConstants.MIPS_LOW26) << 2;
				value |= (oldValue & 0xf0000000);
				value += base;
				newValue = oldValue & 0xfc000000;
				newValue |= (value << 4) >> 6;
				break;
			case R_MIPS_MHI16:
				if (elfRelocationContext.getElfHeader().e_type() == ET_IRX2) {
					markAsError(program, relocationAddress, relocation.getType(),
						symbolName, ILLEGAL_RELOCATION_MESSAGE, log);
					return RelocationResult.FAILURE;
				}
				ElfRelocation nextReloc = getNextRelocation(
					elfRelocationContext, relocation);
				if (nextReloc == null || nextReloc.getType() != R_MIPS_ADDEND) {
					markAsError(program, relocationAddress, relocation.getType(),
						symbolName, ILLEGAL_MHI16_MESSAGE, log);
					return RelocationResult.FAILURE;
				}
				value =  (int) nextReloc.getOffset()+base;
				value = (((value >> 15) + 1) >> 1) & LOW_MASK;
				int offset = 0;
				Address currentAddress = relocationAddress;
				int byteLength = 0;
				do {
					oldValue = memory.getInt(currentAddress);
					offset = ((oldValue & LOW_MASK) << 16) >> 14;
					newValue = oldValue & HIGH_MASK;
					newValue |= value;
					memory.setInt(currentAddress, newValue);
					currentAddress = currentAddress.add(offset);
					byteLength += 4;
				} while(offset != 0);
				return new RelocationResult(Status.APPLIED, byteLength);
			case R_MIPS_DVP_27_S4:
				/*
				HOWTO (R_MIPS_DVP_27_S4,	  // type //
				4,					 // rightshift //
				2,					 // size (0 = byte, 1 = short, 2 = long) //
				27,					// bitsize //
				FALSE,				 // pc_relative //
				4,					 // bitpos //
				complain_overflow_unsigned, // complain_on_overflow //
				bfd_elf_generic_reloc, // special_function //
				"R_MIPS_DVP_27_S4",	// name //
				FALSE,				 // partial_inplace //
				0x7ffffff0,			// src_mask //
				0x7ffffff0,			// dst_mask //
				FALSE);				// pcrel_offset //
				*/
				value = oldValue & DVP_MASK;
				value += base;
				newValue = oldValue & ~DVP_MASK;
				newValue |= value & DVP_MASK;
				break;
			case R_MIPS_ADDEND:
				// already accounted for
				return RelocationResult.SKIPPED;
			case R_MIPS15_S3:
				/*
					HOWTO (R_MIPS15_S3,           /* type 
						3,                     /* rightshift 
						2,                     /* size (0 = byte, 1 = short, 2 = long) 
						15,                    /* bitsize 
						FALSE,                 /* pc_relative 
						6,                     /* bitpos 
						complain_overflow_bitfield, /* complain_on_overflow 
						bfd_elf_generic_reloc, /* special_function 
						"R_MIPS15_S3",         /* name 
						TRUE,                  /* partial_inplace 
						0x001fffc0,            /* src_mask 
						0x001fffc0,            /* dst_mask 
						FALSE);                /* pcrel_offset 
				*/
				value = (oldValue + base) & 0x001fffc0;
				newValue = (oldValue & ~0x001fffc0) | (value >> 3);
				break;
			case R_MIPS_DVP_11_PCREL:
				/*
					HOWTO (R_MIPS_DVP_11_PCREL,   /* type 
						3,                     /* rightshift 
						2,                     /* size (0 = byte, 1 = short, 2 = long) 
						11,                    /* bitsize 
						TRUE,                  /* pc_relative 
						0,                     /* bitpos 
						complain_overflow_signed, /* complain_on_overflow 
						bfd_elf_generic_reloc, /* special_function 
						"R_MIPS_DVP_11_PCREL", /* name 
						FALSE,                 /* partial_inplace 
						0x7ff,                 /* src_mask 
						0x7ff,                 /* dst_mask 
						TRUE);                 /* pcrel_offset 
				*/
				value = (oldValue + base) & 0x7ff;
				newValue = (oldValue & ~0x7ff) | (value >> 3);
				break;
			case R_MIPS_DVP_11_S4:
				/*
					HOWTO (R_MIPS_DVP_11_S4,      /* type 
						4,                     /* rightshift 
						2,                     /* size (0 = byte, 1 = short, 2 = long) 
						11,                    /* bitsize 
						FALSE,                 /* pc_relative 
						0,                     /* bitpos 
						complain_overflow_signed, /* complain_on_overflow 
						bfd_elf_generic_reloc, /* special_function 
						"R_MIPS_DVP_11_S4",    /* name 
						FALSE,                 /* partial_inplace 
						0x03ff,                /* src_mask 
						0x03ff,                /* dst_mask 
						FALSE);                /* pcrel_offset 
				*/
				value = (oldValue + base) & 0x03ff;
				newValue = (oldValue & ~0x03ff) | (value >> 4);
				break;
			case R_MIPS_DVP_U15_S3:
				/*
					HOWTO (R_MIPS_DVP_U15_S3,     /* type 
						3,                     /* rightshift 
						2,                     /* size (0 = byte, 1 = short, 2 = long) 
						15,                    /* bitsize 
						FALSE,                 /* pc_relative 
						0,                     /* bitpos 
						complain_overflow_unsigned, /* complain_on_overflow 
						dvp_u15_s3_reloc,      /* special_function 
						"R_MIPS_DVP_U15_S3",   /* name 
						FALSE,                 /* partial_inplace 
						0xf03ff,               /* src_mask 
						0xf03ff,               /* dst_mask 
						FALSE);                /* pcrel_offset 
				*/
				value = ((oldValue + base) >> 3) & 0xf03ff;
				newValue = (oldValue & ~0xf03ff) | value;
				break;
			default:
				String msg = String.format("Unexpected relocation type %d", relocation.getType());
				bMan.setBookmark(relocationAddress, BookmarkType.ERROR, BookmarkType.ERROR, msg);
			case MIPS_ElfRelocationConstants.R_MIPS_NONE:
			case MIPS_ElfRelocationConstants.R_MIPS_HI16:
			case MIPS_ElfRelocationConstants.R_MIPS_LO16:
			case MIPS_ElfRelocationConstants.R_MIPS_GPREL16:
				return RelocationResult.UNSUPPORTED;
		}

		memory.setInt(relocationAddress, newValue);
		
		return new RelocationResult(Status.APPLIED, 4);
	}

	private ElfRelocation getNextRelocation(ElfRelocationContext context,
		ElfRelocation relocation) {
			ElfHeader elf = context.getElfHeader();
			int index = relocation.getRelocationIndex();
			for (ElfRelocationTable table : elf.getRelocationTables()) {
				ElfRelocation[] relocations = table.getRelocations();
				if (index < relocations.length) {
					if (relocations[index].equals(relocation)) {
						return relocations[index+1];
					}
				}
			}
			return null;
		}

}
