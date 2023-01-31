package ghidra.emotionengine.symboltable;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.exporter.ElfExporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class StabsImporter extends FlatProgramAPI {

	public static class ImportOptions {
		boolean importDataTypes = true;
		boolean importFunctions = true;
		boolean importGlobals = true;
		boolean markInlinedCode = true;
		boolean outputLineNumbers = true;
		String overrideElfPath = "";
		String overrideJsonPath = "";
	}
	
	Program program;
	ImportOptions options;
	TaskMonitor monitor;
	MessageLog log;
	
	ArrayList<File> temporaryFiles = new ArrayList<>();
	
	public StabsImporter(Program p, ImportOptions o, TaskMonitor m, MessageLog l) {
		super(p, m);
		program = p;
		options = o;
		monitor = m;
		log = l;
	}

	public boolean doImport() {
		monitor.setMessage("STABS - Starting...");
		
		File elfFile = null;
		byte[] jsonOutput = null;
		if(options.overrideJsonPath.isBlank()) {
			// Determine where to load the ELF file from, or create it from the
			// current program if a path wasn't manually specified.
			if(options.overrideElfPath.isBlank()) {
				// The ELF file doesn't already exist, so here we create a
				// new temporary file.
				try {
					elfFile = File.createTempFile("stdump_input_", ".elf");
				} catch (IOException e) {
					log.appendException(e);
					cleanup();
					return false;
				}
				temporaryFiles.add(elfFile);
				
				// Write the contents of the current program to the ELF file.
				// TODO: Switch to using OriginalFileExporter instead of
				// ElfExporter when the next Ghidra update comes out.
				ElfExporter exporter = new ElfExporter();
				if(exporter.canExportDomainObject(program.getClass())) {
					try {
						monitor.setMessage("STABS - Writing temporary ELF file...");
						exporter.export(elfFile, program, null, monitor);
					} catch (ExporterException | IOException e) {
						log.appendException(e);
						cleanup();
						return false;
					}
				} else {
					log.appendMsg("ElfExporter.canExportDomainObject(program.getClass()) returned false.");
					cleanup();
					return false;
				}
			} else {
				// A custom ELF file was specified, so we don't create one.
				elfFile = new File(options.overrideElfPath);
			}
			
			// Run stdump.
			try {
				monitor.setMessage("STABS - Running stdump...");
				jsonOutput = runStdump(elfFile.getAbsolutePath(), monitor, log);
				if(jsonOutput == null) {
					cleanup();
					return false;
				}
			} catch (IOException e) {
				log.appendException(e);
				cleanup();
				return false;
			}
		} else {
			// A custom JSON file was specified, so we don't need to run stdump.
			File jsonFile = new File(options.overrideJsonPath);
			try {
				FileInputStream stream = new FileInputStream(jsonFile);
				jsonOutput = stream.readAllBytes();
				stream.close();
			} catch (IOException e) {
				log.appendException(e);
				cleanup();
				return false;
			}
		}
		
		// Parse the JSON file into an AST.
		monitor.setMessage("STABS - Parsing AST...");
		StdumpAST.ParsedJsonFile ast;
		try {
			ast = StdumpParser.readJson(jsonOutput);
		} catch (FileNotFoundException e) {
			log.appendException(e);
			cleanup();
			return false;
		}
		
		// Now actually import all this data into Ghidra.
		StdumpAST.ImporterState importer = new StdumpAST.ImporterState();
		importer.markInlinedCode = options.markInlinedCode;
		importer.outputLineNumbers = options.outputLineNumbers;
		importer.ast = ast;
		importer.monitor = monitor;
		importer.log = log;
		importer.programTypeManager = program.getDataTypeManager();
		if(options.importDataTypes) {
			importDataTypes(importer);
		}
		if(options.importFunctions) {
			importFunctions(importer, program);
		}
		if(options.importGlobals) {
			importGlobalVariables(importer);
		}
		
		cleanup();
		return true;
	}
	
	public void cleanup() {
		for(File file : temporaryFiles) {
			if(!file.delete()) {
				log.appendMsg("Failed to delete temporary file: " + file.getAbsolutePath());
			}
		}
		temporaryFiles.clear();
	}
	
	public void importDataTypes(StdumpAST.ImporterState importer) {
		int type_count = importer.ast.deduplicatedTypes.size();
		
		monitor.setMessage("STABS - Importing data types...");
		monitor.setMaximum(type_count * 2);
		monitor.setProgress(0);
		
		// Gather information required for type lookup.
		for(StdumpAST.Node node : importer.ast.files) {
			StdumpAST.SourceFile file = (StdumpAST.SourceFile) node;
			importer.stabsTypeNumberToDeduplicatedTypeIndex.add(file.stabsTypeNumberToDeduplicatedTypeIndex);
		}

		for(int i = 0; i < type_count; i++) {
			StdumpAST.Node node = importer.ast.deduplicatedTypes.get(i);
			if(node.name != null && !node.name.isEmpty()) {
				importer.typeNameToDeduplicatedTypeIndex.put(node.name, i);
			}
		}

		// Create all the top-level enums, structs and unions first.
		for(int i = 0; i < type_count; i++) {
			StdumpAST.Node node = importer.ast.deduplicatedTypes.get(i);
			if(node instanceof StdumpAST.InlineEnum) {
				StdumpAST.InlineEnum inline_enum = (StdumpAST.InlineEnum) node;
				DataType type = inline_enum.createType(importer);
				importer.types.add(importer.programTypeManager.addDataType(type, null));
			} else if(node instanceof StdumpAST.InlineStructOrUnion) {
				StdumpAST.InlineStructOrUnion struct_or_union = (StdumpAST.InlineStructOrUnion) node;
				DataType type = struct_or_union.create_empty(importer);
				importer.types.add(importer.programTypeManager.addDataType(type, null));
			} else {
				importer.types.add(null);
			}
			monitor.setProgress(i);
		}

		// Fill in the structs and unions recursively.
		for(int i = 0; i < type_count; i++) {
			StdumpAST.Node node = importer.ast.deduplicatedTypes.get(i);
			if(node instanceof StdumpAST.InlineStructOrUnion) {
				StdumpAST.InlineStructOrUnion struct_or_union = (StdumpAST.InlineStructOrUnion) node;
				DataType type = importer.types.get(i);
				struct_or_union.fill(type, importer);
				importer.types.set(i, type);
			}
			monitor.setProgress(type_count + i);
		}
	}
	
	public void importFunctions(StdumpAST.ImporterState importer, Program program) {
		monitor.setMessage("STABS - Importing functions...");
		monitor.setMaximum(importer.ast.files.size());
		monitor.setProgress(0);
		
		for(int i = 0; i < importer.ast.files.size(); i++) {
			StdumpAST.SourceFile sourceFile = (StdumpAST.SourceFile) importer.ast.files.get(i);
			for(StdumpAST.Node function_node : sourceFile.functions) {
				StdumpAST.FunctionDefinition def = (StdumpAST.FunctionDefinition) function_node;
				StdumpAST.FunctionType type = (StdumpAST.FunctionType) def.type;
				if(def.addressRange.valid()) {
					// Find or create the function.
					Address low = toAddr(def.addressRange.low);
					Address high = toAddr(def.addressRange.high - 1);
					AddressSet range = new AddressSet(low, high);
					Function function = findOrCreateFunction(def, low, high, range);
					setFunctionName(function, def, sourceFile, low);
					if(type.returnType != null) {
						try {
							function.setReturnType(type.returnType.createType(importer), SourceType.ANALYSIS);
						} catch (InvalidInputException e) {
							log.appendException(e);
						}
					}
					HashSet<String> parameterNames = fillInParameters(function, importer, def, type);
					if(importer.outputLineNumbers) {
						for(StdumpAST.LineNumberPair pair : def.lineNumbers) {
							setEOLComment(toAddr(pair.address), "Line " + Integer.toString(pair.lineNumber));
						}
					}
					if(importer.markInlinedCode) {
						markInlinedCode(def, sourceFile);
					}
					fillInLocalVariables(function, importer, def, parameterNames);
				}
			}
			
			monitor.setProgress(i);
		}
	}

	private Function findOrCreateFunction(StdumpAST.FunctionDefinition def, Address low, Address high, AddressSet range) {
		Function function = getFunctionAt(low);
		if(function == null) {
			CreateFunctionCmd cmd;
			if(high.getOffset() < low.getOffset()) {
				cmd = new CreateFunctionCmd(new AddressSet(low), SourceType.ANALYSIS);
			} else {
				cmd = new CreateFunctionCmd(def.name, low, range, SourceType.ANALYSIS);
			}
			boolean success = cmd.applyTo(program, monitor);
			if(!success) {
				log.appendMsg("Failed to create function " + def.name + ": " + cmd.getStatusMsg());
			}
			function = getFunctionAt(low);
		}
		return function;
	}
	
	private void setFunctionName(Function function, StdumpAST.FunctionDefinition def,
			StdumpAST.SourceFile sourceFile, Address low) {
		// Remove spam like "gcc2_compiled." and remove the existing label for
		// the function name so it can be reapplied below.
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol[] existing_symbols = symbolTable.getSymbols(low);
		for(Symbol existing_symbol : existing_symbols) {
			String name = existing_symbol.getName();
			if(name.equals("__gnu_compiled_cplusplus") || name.equals("gcc2_compiled.") || name.equals(def.name)) {
				symbolTable.removeSymbolSpecial(existing_symbol);
			}
		}
		
		// Ghidra will sometimes find the wrong label and use it as a function
		// name e.g. "gcc2_compiled." so it's important that we set the name
		// explicitly here.
		try {
			function.setName(def.name, SourceType.ANALYSIS);
		} catch (DuplicateNameException | InvalidInputException e) {
			log.appendException(e);
		}
		function.setComment(sourceFile.path);
	}
	
	private HashSet<String> fillInParameters(Function function, StdumpAST.ImporterState importer,
			StdumpAST.FunctionDefinition def, StdumpAST.FunctionType type) {
		HashSet<String> parameter_names = new HashSet<>();
		if(type.parameters.size() > 0) {
			ArrayList<Variable> parameters = new ArrayList<>();
			for(int i = 0; i < type.parameters.size(); i++) {
				StdumpAST.Variable variable = (StdumpAST.Variable) type.parameters.get(i);
				DataType parameter_type = StdumpAST.replaceVoidWithUndefined1(variable.type.createType(importer));
				if(variable.storage.isByReference) {
					parameter_type = new PointerDataType(parameter_type);
				}
				try {
					parameters.add(new ParameterImpl(variable.name, parameter_type, program));
				} catch (InvalidInputException e) {
					log.appendException(e);
				}
				parameter_names.add(variable.name);
			}
			try {
				function.replaceParameters(parameters, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
			} catch(DuplicateNameException | InvalidInputException exception) {
				log.appendMsg("Failed to setup parameters for " + def.name + ": " + exception.getMessage());
			}
		}
		return parameter_names;
	}
	
	private void markInlinedCode(StdumpAST.FunctionDefinition def, StdumpAST.SourceFile sourceFile) {
		String path;
		if(def.relativePath != null) {
			path = def.relativePath;
		} else {
			path = sourceFile.relativePath;
		}
		boolean was_inlining = false;
		for(StdumpAST.SubSourceFile sub : def.subSourceFiles) {
			boolean is_inlining = !sub.relativePath.equals(path);
			if(is_inlining && !was_inlining) {
				setPreComment(toAddr(sub.address), "inlined from " + sub.relativePath);
			} else if(!is_inlining && was_inlining) {
				setPreComment(toAddr(sub.address), "end of inlined section");
			}
			was_inlining = is_inlining;
		}
	}
	
	private void fillInLocalVariables(Function function, StdumpAST.ImporterState importer,
			StdumpAST.FunctionDefinition def, HashSet<String> parameter_names) {
		// Add local variables.
		HashMap<String, StdumpAST.Variable> stack_locals = new HashMap<>();
		for(StdumpAST.Node child : def.locals) {
			if(child instanceof StdumpAST.Variable && !parameter_names.contains(child.name)) {
				StdumpAST.Variable src = (StdumpAST.Variable) child;
				if(src.storageClass != StdumpAST.StorageClass.STATIC && src.storage.type == StdumpAST.VariableStorageType.STACK) {
					stack_locals.put(src.name, src);
				}
			}
		}
		for(Map.Entry<String, StdumpAST.Variable> local : stack_locals.entrySet()) {
			StdumpAST.Variable var = local.getValue();
			DataType localType = StdumpAST.replaceVoidWithUndefined1(var.type.createType(importer));
			LocalVariable dest;
			try {
				dest = new LocalVariableImpl(var.name, localType, var.storage.stackPointerOffset, program, SourceType.ANALYSIS);
				function.addLocalVariable(dest, SourceType.ANALYSIS);
			} catch (DuplicateNameException | InvalidInputException e) {
				log.appendException(e);
			}
		}
	}
	
	public void importGlobalVariables(StdumpAST.ImporterState importer) {
		monitor.setMessage("STABS - Importing global variables...");
		monitor.setMaximum(importer.ast.files.size());
		monitor.setProgress(0);
		
		AddressSpace space = getAddressFactory().getDefaultAddressSpace();
		for(int i = 0; i < importer.ast.files.size(); i++) {
			StdumpAST.SourceFile file = (StdumpAST.SourceFile) importer.ast.files.get(i);
			for(StdumpAST.Node global_node : file.globals) {
				StdumpAST.Variable global = (StdumpAST.Variable) global_node;
				if(global.storage.global_address > -1) {
					Address address = space.getAddress(global.storage.global_address);
					DataType type = StdumpAST.replaceVoidWithUndefined1(global.type.createType(importer));
					try {
						DataUtilities.createData(currentProgram, address, type, type.getLength(), false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
					} catch (CodeUnitInsertionException e) {
						log.appendException(e);
					}
					try {
						this.createLabel(address, global.name, true);
					} catch (Exception e) {
						log.appendException(e);
					}
				}
			}
			
			monitor.setProgress(i);
		}
	}
	
	public static byte[] runStdump(String elfPath, TaskMonitor monitor, MessageLog log) throws IOException {
		String executableName = "stdump" + Platform.CURRENT_PLATFORM.getExecutableExtension();
		File executable = Application.getOSFile(executableName);
		String[] command = {
				executable.getAbsolutePath(),
				"print_json",
				elfPath
		};
		Process process = Runtime.getRuntime().exec(command);
		InputStream stdout = process.getInputStream();
		InputStream stderr = process.getErrorStream();
		BufferedReader errorReader = new BufferedReader(new InputStreamReader(stderr));
		boolean isBad = false;
		while(errorReader.ready()) {
			log.appendMsg("stdump", errorReader.readLine());
			isBad = true;
		}
		if(!isBad) {
			return stdout.readAllBytes();
		} else {
			return null;
		}
		
	}

}
