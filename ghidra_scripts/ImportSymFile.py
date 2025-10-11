# Import function names from a .sym file and apply them to the current program.
# @category ghidra-emotionengine
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import re
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SourceType

def parse_sym_line(line):
    """
    Parse a line from a .sym file.
    
    Supports two formats:
    - Format 1 (with size): "00100008 _start,0210"
    - Format 2 (without size): "00100008 _start"
    
    Returns:
        tuple: (address_string, function_name) or None if line is invalid
    """
    line = line.strip()
    
    # Skip empty lines or comments
    if not line or line.startswith('#') or line.startswith('//'):
        return None
    
    # Split on whitespace
    parts = line.split(None, 1)  # Split on first whitespace only
    if len(parts) != 2:
        return None
    
    address_str, name_part = parts
    
    # Validate address format (hex string)
    if not re.match(r'^[0-9A-Fa-f]+$', address_str):
        return None
    
    # Extract function name (remove size if present)
    # Format: "function_name,size" or just "function_name"
    if ',' in name_part:
        function_name = name_part.split(',')[0]
    else:
        function_name = name_part
    
    # Clean up function name
    function_name = function_name.strip()
    
    if not function_name:
        return None
    
    return (address_str, function_name)

def import_sym_file():
    """Main function to import .sym file and apply function names."""
    
    # Validate that a program is loaded
    if currentProgram is None:
        printerr("No program is currently loaded")
        return
    
    # Use askFile to get the .sym file from the user
    # This method is provided by GhidraScript and works in both GUI and headless modes
    try:
        selected_file = askFile("Select .sym File to Import", "Import")
    except:
        # User cancelled the dialog
        println("No file selected, import cancelled")
        return
    
    if selected_file is None:
        println("No file selected, import cancelled")
        return
    
    println(f"Importing symbols from: {selected_file.absolutePath}")
    println("-" * 60)
    
    # Initialize API and counters
    flat_api = FlatProgramAPI(currentProgram)
    function_manager = currentProgram.functionManager
    address_factory = currentProgram.addressFactory
    
    total_lines = 0
    functions_created = 0
    functions_renamed = 0
    errors = 0
    skipped = 0
    
    try:
        # Read and process the .sym file
        with open(selected_file.absolutePath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                
                # Parse the line
                parsed = parse_sym_line(line)
                if parsed is None:
                    skipped += 1
                    continue
                
                address_str, function_name = parsed
                
                try:
                    # Convert address string to Ghidra Address object
                    # Prepend "0x" if not present for proper parsing
                    if not address_str.startswith('0x'):
                        address_str = '0x' + address_str
                    
                    address = address_factory.getAddress(address_str)
                    
                    if address is None:
                        printerr(f"Line {line_num}: Invalid address '{address_str}'")
                        errors += 1
                        continue
                    
                    # Check if address is valid in program memory
                    if not currentProgram.memory.contains(address):
                        printerr(f"Line {line_num}: Address {address} is not in program memory")
                        errors += 1
                        continue
                    
                    # Check if function exists at this address
                    function = function_manager.getFunctionAt(address)
                    
                    # If no function exists, create one
                    if function is None:
                        try:
                            function = flat_api.createFunction(address, function_name)
                            if function is not None:
                                functions_created += 1
                                println(f"Created function '{function_name}' at {address}")
                            else:
                                printerr(f"Line {line_num}: Failed to create function at {address}")
                                errors += 1
                                continue
                        except Exception as e:
                            printerr(f"Line {line_num}: Error creating function at {address}: {str(e)}")
                            errors += 1
                            continue
                    
                    # Apply the function name
                    try:
                        old_name = function.name
                        function.setName(function_name, SourceType.USER_DEFINED)
                        
                        if old_name != function_name:
                            functions_renamed += 1
                            println(f"Renamed function at {address}: '{old_name}' -> '{function_name}'")
                        
                    except Exception as e:
                        printerr(f"Line {line_num}: Error setting function name at {address}: {str(e)}")
                        errors += 1
                        continue
                
                except Exception as e:
                    printerr(f"Line {line_num}: Unexpected error processing '{line.strip()}': {str(e)}")
                    errors += 1
                    continue
        
        # Print summary
        println("-" * 60)
        println("Import Summary:")
        println(f"  Total lines processed: {total_lines}")
        println(f"  Functions created: {functions_created}")
        println(f"  Functions renamed: {functions_renamed}")
        println(f"  Lines skipped (empty/comments): {skipped}")
        println(f"  Errors: {errors}")
        println("-" * 60)
        
        if errors == 0:
            println("Import completed successfully!")
        else:
            println(f"Import completed with {errors} error(s). Check output for details.")
    
    except Exception as e:
        printerr(f"Fatal error reading file: {str(e)}")
        import traceback
        printerr(traceback.format_exc())

# Run the import
import_sym_file()