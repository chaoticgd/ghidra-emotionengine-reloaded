/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.emotionengine.dvp;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer to synchronize symbols from .vutext blocks to DVP overlay blocks.
 * 
 * DVP overlay blocks are byte-mapped blocks that reference .vutext memory but do not
 * automatically share symbols. This analyzer runs after StabsAnalyzer and copies all
 * symbols from the source block to the corresponding addresses in overlay blocks.
 */
public class DvpOverlayLabelSyncAnalyzer extends AbstractAnalyzer {
	
	private static final String NAME = "DVP Overlay Label Sync";
	private static final String DESCRIPTION =
		"Synchronizes symbols from .vutext to DVP overlay blocks. " +
		"Byte-mapped overlay blocks reference .vutext memory but do not " +
		"automatically share symbols. This analyzer copies symbols from " +
		"source blocks to overlay blocks after symbol analysis completes.";
	
	private static final String DVP_OVERLAY_PREFIX = ".DVP.overlay..";
	
	// Pattern to match VU-related temporary symbols like "vu.0", ".vu.1", etc.
	// These symbols don't contain useful information and should be skipped
	private static final Pattern VU_TEMP_SYMBOL_PATTERN = Pattern.compile("\\.?vu\\.\\d+");
	
	public DvpOverlayLabelSyncAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// Run after StabsAnalyzer and other symbol analyzers
		// StabsAnalyzer uses FORMAT_ANALYSIS.after(), so we use after().after()
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after().after());
		setDefaultEnablement(true);
	}
	
	@Override
	public boolean canAnalyze(Program program) {
		// Check if there are any DVP overlay blocks
		Memory memory = program.getMemory();
		for (MemoryBlock block : memory.getBlocks()) {
			if (block.getName().startsWith(DVP_OVERLAY_PREFIX)) {
				return true;
			}
		}
		return false;
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		Memory memory = program.getMemory();
		SymbolTable symbolTable = program.getSymbolTable();
		
		int overlaysProcessed = 0;
		int symbolsCopied = 0;
		int symbolsSkipped = 0;
		
		// Iterate through all memory blocks to find DVP overlays
		for (MemoryBlock overlayBlock : memory.getBlocks()) {
			monitor.checkCancelled();
			
			String blockName = overlayBlock.getName();
			if (!blockName.startsWith(DVP_OVERLAY_PREFIX)) {
				continue;
			}
			
			if (!overlayBlock.isMapped()) {
				Msg.warn(this, "DVP overlay block '" + blockName + 
					"' is not byte-mapped, skipping");
				continue;
			}
			
			overlaysProcessed++;
			monitor.setMessage("Processing DVP overlay: " + blockName);
			
			try {
				Address overlayStart = overlayBlock.getStart();
				long blockSize = overlayBlock.getSize();
				
				// For byte-mapped blocks, get the source address from MemoryBlockSourceInfo
				List<MemoryBlockSourceInfo> sourceInfos = overlayBlock.getSourceInfos();
				if (sourceInfos.isEmpty()) {
					Msg.warn(this, "No source info found for overlay block '" +
						blockName + "', skipping");
					continue;
				}
				
				// Get the first source info (should only be one for simple byte-mapped blocks)
				MemoryBlockSourceInfo sourceInfo = sourceInfos.get(0);
				Optional<AddressRange> mappedRangeOpt = sourceInfo.getMappedRange();
				
				if (!mappedRangeOpt.isPresent()) {
					Msg.warn(this, "No mapped range found for overlay block '" +
						blockName + "', skipping");
					continue;
				}
				
				AddressRange mappedRange = mappedRangeOpt.get();
				Address firstSourceAddr = mappedRange.getMinAddress();
				
				// Find the source block containing this address
				MemoryBlock sourceBlock = memory.getBlock(firstSourceAddr);
				if (sourceBlock == null) {
					Msg.warn(this, "Could not find source block for overlay '" + 
						blockName + "', skipping");
					continue;
				}
				
				Msg.info(this, String.format("Syncing symbols from '%s' to '%s'",
					sourceBlock.getName(), blockName));
				
				// Start transaction for symbol creation
				int txId = program.startTransaction("Sync DVP Overlay Symbols: " + blockName);
				try {
					// Iterate through all symbols in the source block address range
					Address sourceStart = firstSourceAddr;
					Address sourceEnd = sourceStart.add(blockSize - 1);
					
					SymbolIterator symbols = symbolTable.getSymbolIterator(sourceStart, true);
					
					while (symbols.hasNext()) {
						monitor.checkCancelled();
						Symbol sourceSymbol = symbols.next();
						
						Address symbolAddr = sourceSymbol.getAddress();
						
						// Check if symbol is within the mapped range
						if (symbolAddr.compareTo(sourceEnd) > 0) {
							break; // Past our range
						}
						
						if (symbolAddr.compareTo(sourceStart) < 0) {
							continue; // Before our range
						}
						
						// Skip certain symbol types
						if (sourceSymbol.getSource() == SourceType.DEFAULT) {
							symbolsSkipped++;
							continue; // Skip default symbols
						}
						
						String symbolName = sourceSymbol.getName();
						
						// Skip VU temporary symbols (e.g., "vu.0", ".vu.1")
						if (VU_TEMP_SYMBOL_PATTERN.matcher(symbolName).matches()) {
							symbolsSkipped++;
							continue;
						}
						
						// Calculate offset from source block start
						long offset = symbolAddr.subtract(sourceStart);
						
						// Calculate corresponding overlay address
						Address overlayAddr = overlayStart.add(offset);
						
						// Check if symbol already exists at overlay address
						Symbol[] existingSymbols = symbolTable.getSymbols(overlayAddr);
						boolean symbolExists = false;
						for (Symbol existing : existingSymbols) {
							if (existing.getName().equals(symbolName) && 
								existing.getSource() != SourceType.DEFAULT) {
								symbolExists = true;
								symbolsSkipped++;
								break;
							}
						}
						
						if (symbolExists) {
							continue; // Symbol already exists, skip
						}
						
						// Create the symbol at the overlay address
						try {
							symbolTable.createLabel(
								overlayAddr, 
								symbolName, 
								sourceSymbol.getParentNamespace(),
								SourceType.ANALYSIS);
							symbolsCopied++;
						} catch (InvalidInputException e) {
							// Try with a modified name if there's a naming conflict
							try {
								String newName = symbolName + "_ovl";
								symbolTable.createLabel(
									overlayAddr, 
									newName,
									sourceSymbol.getParentNamespace(),
									SourceType.ANALYSIS);
								symbolsCopied++;
								Msg.info(this, String.format(
									"Renamed symbol '%s' to '%s' at %s due to conflict",
									symbolName, newName, overlayAddr));
							} catch (InvalidInputException e2) {
								Msg.warn(this, String.format(
									"Failed to create symbol '%s' at %s: %s",
									symbolName, overlayAddr, e2.getMessage()));
								symbolsSkipped++;
							}
						}
					}
					
					program.endTransaction(txId, true);
					
					Msg.info(this, String.format(
						"Overlay '%s': copied %d symbols, skipped %d symbols",
						blockName, symbolsCopied, symbolsSkipped));
					
				} catch (Exception e) {
					program.endTransaction(txId, false);
					throw e;
				}
				
			} catch (Exception e) {
				Msg.error(this, "Error processing DVP overlay block '" + blockName + "': " + 
					e.getMessage(), e);
				log.appendException(e);
			}
		}
		
		if (overlaysProcessed > 0) {
			Msg.info(this, String.format(
				"DVP Overlay Label Sync complete: Processed %d overlay blocks, " +
				"copied %d symbols total, skipped %d symbols total",
				overlaysProcessed, symbolsCopied, symbolsSkipped));
		} else {
			Msg.info(this, "DVP Overlay Label Sync: No overlay blocks found to process");
		}
		
		return true;
	}
}