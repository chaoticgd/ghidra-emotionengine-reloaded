# Export VU (DVP) overlay data: binary data (.bin) and symbols (.sym)
# @category ghidra-emotionengine
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import os
import re
from collections import defaultdict
from ghidra.program.model.symbol import SourceType
import jpype

# Constants from DvpOverlayTable.java
VU1_TEXT_ADDRESS = 0x11008000
DVP_OVERLAY_PREFIX = ".DVP.overlay.."
VU_INSTRUCTION_SIZE = 8  # VU instructions are 8 bytes (64-bit)

class OverlayData:
    """Container for overlay block data grouped by filename hash."""
    
    def __init__(self, filename_hash):
        self.filename_hash = filename_hash
        self.symbols = []  # List of (vu_address, symbol_name) tuples
        self.blocks = []   # List of (vaddr, block) tuples for binary export
    
    def add_symbol(self, vu_address, symbol_name):
        """Add a symbol to this overlay."""
        self.symbols.append((vu_address, symbol_name))
    
    def add_block(self, vaddr, block):
        """Add a memory block to this overlay."""
        self.blocks.append((vaddr, block))
    
    def get_sorted_symbols(self):
        """Get symbols sorted by address."""
        return sorted(self.symbols, key=lambda x: x[0])
    
    def get_sorted_blocks(self):
        """Get blocks sorted by vaddr."""
        return sorted(self.blocks, key=lambda x: x[0])

def parse_overlay_block_name(block_name):
    """
    Parse DVP overlay block name to extract components.
    
    Format: .DVP.overlay..<overlay_name_offset>.<filename_hash>.<vaddr>.<line_of_split>.<counter>
    Example: .DVP.overlay..0x0000.a1b2c3d4.0x0100.0042.1
    
    Returns:
        dict with keys: overlay_name_offset, filename_hash, vaddr, line_of_split, counter
        or None if parsing fails
    """
    if not block_name.startswith(DVP_OVERLAY_PREFIX):
        return None
    
    # Remove prefix and split by dots
    remainder = block_name[len(DVP_OVERLAY_PREFIX):]
    parts = remainder.split('.')
    
    if len(parts) < 5:
        return None
    
    try:
        return {
            'overlay_name_offset': parts[0],  # e.g., "0x0000"
            'filename_hash': parts[1],        # e.g., "a1b2c3d4"
            'vaddr': parts[2],                # e.g., "0x0100"
            'line_of_split': parts[3],        # e.g., "0042"
            'counter': parts[4]               # e.g., "1"
        }
    except (IndexError, ValueError):
        return None

def convert_vu_address(address_offset):
    """
    Convert Ghidra address to VU instruction address.
    
    Subtracts VU1_TEXT_ADDRESS base and divides by 8 (instruction word size).
    
    Args:
        address_offset: The address offset as a long
        
    Returns:
        VU instruction address as integer
    """
    relative_offset = address_offset - VU1_TEXT_ADDRESS
    vu_address = relative_offset // VU_INSTRUCTION_SIZE
    return int(vu_address)

def collect_overlay_data(memory, symbol_table):
    """
    Collect all overlay data from memory blocks.
    
    Returns:
        dict: filename_hash -> OverlayData mapping
    """
    overlays = defaultdict(lambda: OverlayData(None))
    overlay_blocks_found = 0
    total_symbols = 0
    
    # Iterate through all memory blocks
    for block in memory.blocks:
        block_name = block.name
        
        # Check if this is a DVP overlay block
        if not block_name.startswith(DVP_OVERLAY_PREFIX):
            continue
        
        # Parse the block name
        parsed = parse_overlay_block_name(block_name)
        if parsed is None:
            printerr(f"Warning: Could not parse overlay block name: {block_name}")
            continue
        
        filename_hash = parsed['filename_hash']
        vaddr = parsed['vaddr']
        overlay_blocks_found += 1
        
        println(f"Processing overlay block: {block_name}")
        println(f"  Filename hash: {filename_hash}")
        
        # Initialize overlay data if needed
        if overlays[filename_hash].filename_hash is None:
            overlays[filename_hash].filename_hash = filename_hash
        
        # Parse vaddr for sorting blocks
        try:
            vaddr_int = int(vaddr, 16) if vaddr.startswith('0x') else int(vaddr, 16)
        except ValueError:
            vaddr_int = 0
        
        # Add block for binary export
        overlays[filename_hash].add_block(vaddr_int, block)
        
        # Collect symbols from this block
        block_start = block.start
        block_end = block.end
        block_symbol_count = 0
        
        symbol_iter = symbol_table.getSymbolIterator(block_start, True)
        for symbol in symbol_iter:
            symbol_addr = symbol.address
            
            # Check if symbol is within this block
            if symbol_addr.compareTo(block_end) > 0:
                break
            if symbol_addr.compareTo(block_start) < 0:
                continue
            
            # Skip default symbols and VU temporary symbols
            if symbol.source == SourceType.DEFAULT:
                continue
            
            symbol_name = symbol.name
            if re.match(r'\.?vu\.\d+', symbol_name):
                continue
            
            # Convert address and add symbol
            vu_address = convert_vu_address(symbol_addr.offset)
            overlays[filename_hash].add_symbol(vu_address, symbol_name)
            block_symbol_count += 1
            total_symbols += 1
        
        println(f"  Found {block_symbol_count} symbols")
    
    return dict(overlays), overlay_blocks_found, total_symbols

def export_symbol_file(overlay_data, output_path):
    """
    Export symbols to a .sym file.
    
    Args:
        overlay_data: OverlayData instance
        output_path: Directory path for output
        
    Returns:
        bool: True if successful
    """
    filename = f"{overlay_data.filename_hash}.sym"
    filepath = os.path.join(output_path, filename)
    
    try:
        symbols = overlay_data.get_sorted_symbols()
        with open(filepath, 'w', encoding='utf-8') as f:
            for vu_address, symbol_name in symbols:
                # Format: 4 hex digits (no 0x prefix), space, symbol name
                f.write(f"{vu_address:04x} {symbol_name}\n")
        
        println(f"Wrote {len(symbols)} symbols to: {filename}")
        return True
        
    except Exception as e:
        printerr(f"Error writing symbol file {filename}: {str(e)}")
        return False

def export_binary_file(overlay_data, output_path):
    """
    Export raw binary data to a .bin file.
    
    Args:
        overlay_data: OverlayData instance
        output_path: Directory path for output
        
    Returns:
        bool: True if successful
    """
    filename = f"{overlay_data.filename_hash}.bin"
    filepath = os.path.join(output_path, filename)
    
    try:
        blocks = overlay_data.get_sorted_blocks()
        total_bytes = 0
        
        with open(filepath, 'wb') as f:
            for vaddr_int, block in blocks:
                # Get block size and create byte array
                block_size = int(block.size)
                byte_array = jpype.JByte[block_size]
                
                # Read bytes from the block
                bytes_read = block.getBytes(block.start, byte_array)
                
                # Convert Java bytes (signed) to Python bytes (unsigned)
                python_bytes = bytes([(b & 0xFF) for b in byte_array[:bytes_read]])
                
                # Write to file
                f.write(python_bytes)
                total_bytes += bytes_read
        
        println(f"Wrote {total_bytes} bytes to: {filename}")
        return True
        
    except Exception as e:
        printerr(f"Error writing binary file {filename}: {str(e)}")
        import traceback
        printerr(traceback.format_exc())
        return False

def export_dvp_overlays():
    """Main function to export DVP overlay data."""
    
    # Validate that a program is loaded
    if currentProgram is None:
        printerr("No program is currently loaded")
        return
    
    println("Exporting DVP overlay data...")
    println("-" * 60)
    
    # Get output directory from user
    try:
        output_dir = askDirectory("Select Output Directory for DVP Overlay Files", "Select")
    except:
        println("No directory selected, export cancelled")
        return
    
    if output_dir is None:
        println("No directory selected, export cancelled")
        return
    
    output_path = output_dir.absolutePath
    println(f"Output directory: {output_path}")
    println("-" * 60)
    
    # Collect overlay data
    memory = currentProgram.memory
    symbol_table = currentProgram.symbolTable
    
    overlays, overlay_blocks_found, total_symbols = collect_overlay_data(memory, symbol_table)
    
    println("-" * 60)
    println(f"Found {overlay_blocks_found} DVP overlay blocks")
    println(f"Total symbols collected: {total_symbols}")
    println(f"Unique overlays (by filename hash): {len(overlays)}")
    println("-" * 60)
    
    if overlay_blocks_found == 0:
        println("No DVP overlay blocks found in program")
        return
    
    # Export files for each overlay
    sym_files_written = 0
    bin_files_written = 0
    
    for filename_hash, overlay_data in overlays.items():
        # Export symbol file
        if export_symbol_file(overlay_data, output_path):
            sym_files_written += 1
        
        # Export binary file
        if export_binary_file(overlay_data, output_path):
            bin_files_written += 1
    
    # Print summary
    println("-" * 60)
    println("Export complete!")
    println(f"  Symbol files (.sym): {sym_files_written}")
    println(f"  Binary files (.bin): {bin_files_written}")
    println(f"  Total symbols exported: {total_symbols}")
    println(f"  Output directory: {output_path}")
    println("-" * 60)

# Run the export
export_dvp_overlays()