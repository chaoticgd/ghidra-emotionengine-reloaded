// Create a label for each MMIO register in a namespace called "registers".
//@category ghidra-emotionengine

import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class ImportMMIORegisterLabels extends GhidraScript {

    public void run() throws Exception {
        Namespace registerNamespace = getNamespace(null, "registers");
        if(registerNamespace == null) {
            registerNamespace = currentProgram.getSymbolTable().createNameSpace(
                currentProgram.getGlobalNamespace(),
                "registers",
                SourceType.USER_DEFINED
            );
        }
        
        AddressSpace ram = currentProgram.getAddressFactory().getAddressSpace("ram");
        List<Register> registers = currentProgram.getLanguage().getRegisters();
        for(Register register : registers) {
			monitor.checkCancelled();
            if(register.getAddressSpace() == ram) {
                Symbol[] oldSymbols = currentProgram.getSymbolTable().getSymbols(register.getAddress());
                for(Symbol symbol : oldSymbols) {
                    symbol.delete();
                }
                
                currentProgram.getSymbolTable().createLabel(
                    register.getAddress(),
                    register.getName(),
                    registerNamespace,
                    SourceType.USER_DEFINED
                );
            }
        }
    }

}
