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
import ghidra.app.util.exporter.ExporterException;
import ghidra.app.util.exporter.OriginalFileExporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.emotionengine.symboltable.StdumpAST.ImporterState;
import ghidra.emotionengine.symboltable.StdumpAST.StorageClass;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Integer16DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedInteger16DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class StabsImporter extends FlatProgramAPI {

	public static class ImportOptions {
		boolean embedBaseClasses = true;
		boolean importBuiltins = true;
		boolean importFunctions = true;
		boolean importGlobals = true;
		boolean importTypedefs = true;
		boolean markInlinedCode = true;
		boolean outputLineNumbers = true;
		boolean onlyRunOnce = true;
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
					cleanupTemporaryFiles();
					return false;
				}
				temporaryFiles.add(elfFile);
				
				OriginalFileExporter exporter = new OriginalFileExporter();
				if(exporter.canExportDomainObject(program.getClass())) {
					try {
						monitor.setMessage("STABS - Writing temporary ELF file...");
						exporter.export(elfFile, program, null, monitor);
					} catch (ExporterException | IOException e) {
						log.appendException(e);
						cleanupTemporaryFiles();
						return false;
					}
				} else {
					log.appendMsg("ElfExporter.canExportDomainObject(program.getClass()) returned false.");
					cleanupTemporaryFiles();
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
					cleanupTemporaryFiles();
					return false;
				}
			} catch (InterruptedException | IOException e) {
				log.appendException(e);
				cleanupTemporaryFiles();
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
				cleanupTemporaryFiles();
				return false;
			}
		}

		cleanupTemporaryFiles();
		
		if(monitor.isCancelled()) {
			log.appendMsg("STABS", "Import operation cancelled by user.");
			return false;
		}
		
		// Parse the JSON file into an AST.
		monitor.setMessage("STABS - Parsing AST...");
		StdumpAST.ParsedJsonFile ast;
		try {
			ast = StdumpParser.readJson(jsonOutput);
		} catch (FileNotFoundException e) {
			log.appendException(e);
			return false;
		}
		
		if(options.onlyRunOnce && shouldBailOut(program, ast)) {
			log.appendMsg("STABS", "Import operation cancelled since it has already been run.");
			return false;
		}

		
		if(monitor.isCancelled()) {
			log.appendMsg("STABS", "Import operation cancelled by user.");
			return false;
		}
		
		// Now actually import all this data into Ghidra.
		StdumpAST.ImporterState importer = new StdumpAST.ImporterState();
		importer.embedBaseClasses = options.embedBaseClasses;
		importer.markInlinedCode = options.markInlinedCode;
		importer.outputLineNumbers = options.outputLineNumbers;
		importer.ast = ast;
		importer.monitor = monitor;
		importer.log = log;
		importer.programTypeManager = program.getDataTypeManager();
		importDataTypes(importer);
		if(options.importFunctions) {
			importFunctions(importer, program);
		}
		if(options.importGlobals) {
			importGlobalVariables(importer);
		}
		
		return true;
	}
	
	public void cleanupTemporaryFiles() {
		for(File file : temporaryFiles) {
			if(!file.delete()) {
				log.appendMsg("Failed to delete temporary file: " + file.getAbsolutePath());
			}
		}
		temporaryFiles.clear();
	}
	
	 public boolean shouldBailOut(Program program, StdumpAST.ParsedJsonFile ast) {
		if(ast.deduplicatedTypes.size() < 10) {
			return false;
		}
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		int existingTypes = 0;
		int newTypes = 0;
		for(StdumpAST.Node node : ast.deduplicatedTypes) {
			if(dataTypeManager.getDataType("/" + node.name) != null) {
				existingTypes++;
			} else {
				newTypes++;
			}
		}
		return existingTypes > newTypes;
	}

	
	public void importDataTypes(StdumpAST.ImporterState importer) {
		importer.stage = StdumpAST.ImportStage.TYPES;
		
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
			node.setupConflictResolutionPostfix(importer);
			if(node instanceof StdumpAST.InlineEnum) {
				StdumpAST.InlineEnum inlineEnum = (StdumpAST.InlineEnum) node;
				DataType type = inlineEnum.createType(importer);
				importer.types.add(importer.programTypeManager.addDataType(type, STABS_DATA_TYPE_CONFLICT_HANDLER));
			} else if(node instanceof StdumpAST.InlineStructOrUnion) {
				StdumpAST.InlineStructOrUnion structOrUnion = (StdumpAST.InlineStructOrUnion) node;
				boolean isVtablePointerType = structOrUnion.name.equals("__vtbl_ptr_type");
				if(isVtablePointerType) {
					fixVtablePointerType(structOrUnion);
				}
				DataType createdType = structOrUnion.createEmpty(importer);
				DataType addedType = importer.programTypeManager.addDataType(createdType, STABS_DATA_TYPE_CONFLICT_HANDLER);
				if(isVtablePointerType) {
					importer.vtablePointerType = addedType;
				}
				importer.types.add(addedType);
			} else {
				importer.types.add(null);
			}
			monitor.setProgress(i);
		}
		
		// If __vtbl_ptr_type isn't a struct, we assume it's a pointer.
		if(importer.vtablePointerType == null) {
			importer.vtablePointerType = PointerDataType.dataType;
		}
		
		// Create and register typedefs.
		for(int i = 0; i < type_count; i++) {
			StdumpAST.Node node = importer.ast.deduplicatedTypes.get(i);
			boolean isTypeDef = node.storageClass == StorageClass.TYPEDEF;
			if(isTypeDef) {
				boolean isBuiltIn = node instanceof StdumpAST.BuiltIn;
				if(isBuiltIn) {
					if(options.importBuiltins) {
						importer.typedefs.add(createTypedef(node, importer));
						continue;
					}
				} else {
					boolean isEnum = node instanceof StdumpAST.InlineEnum;
					boolean isStructOrUnion = node instanceof StdumpAST.InlineStructOrUnion;
					if(options.importTypedefs && !isEnum && !isStructOrUnion) {
						importer.typedefs.add(createTypedef(node, importer));
						continue;
					}
				}
			}
			importer.typedefs.add(null);
		}
		
		// Fill in the structs and unions recursively.
		for(int i = 0; i < type_count; i++) {
			StdumpAST.Node node = importer.ast.deduplicatedTypes.get(i);
			node.setupConflictResolutionPostfix(importer);
			if(node instanceof StdumpAST.InlineStructOrUnion) {
				StdumpAST.InlineStructOrUnion struct_or_union = (StdumpAST.InlineStructOrUnion) node;
				DataType type = importer.types.get(i);
				StdumpAST.InlineStructOrUnion.fill(type, 0, struct_or_union, struct_or_union, importer);
				importer.types.set(i, type);
			}
			monitor.setProgress(type_count + i);
		}
	}
	
	public void fixVtablePointerType(StdumpAST.InlineStructOrUnion vtablePointerType) {
		// For some compiler versions __vtbl_ptr_type is just a function
		// pointer, for others it's a struct containing some integers and a
		// function pointer. In the latter case, the stab provided in the symbol
		// table leads to incorrect decompilation of virtual function calls, so
		// we need to fix it up here.
		for(StdumpAST.Node field : vtablePointerType.fields) {
			if(field.name.equals("__delta2")) {
				vtablePointerType.fields.remove(field);
				break;
			}
		}
	}
	
	public DataType createTypedef(StdumpAST.Node node, ImporterState importer) {
		DataType underlyingType = node.createType(importer);
		// If Ghidra already has a built-in type with the same name, we don't
		// need to create a typedef for it.
		if(underlyingType instanceof BuiltInDataType && underlyingType.getName().equals(node.name)) {
			return null;
		}
		// The type names provided for 128 bit built-in data types in the symbol
		// table are a bit dodgy and conflict with each other, so here we make
		// sure we don't create typedefs for them.
		if(underlyingType instanceof Integer16DataType || underlyingType instanceof UnsignedInteger16DataType) {
			return null;
		}
		DataType createdType = new TypedefDataType(node.name, underlyingType);
		return importer.programTypeManager.addDataType(createdType, STABS_DATA_TYPE_CONFLICT_HANDLER);
	}
	
	public void importFunctions(StdumpAST.ImporterState importer, Program program) {
		monitor.setMessage("STABS - Importing functions...");
		monitor.setMaximum(importer.ast.files.size());
		monitor.setProgress(0);
		
		removeJunkLabels(program);
		
		for(int i = 0; i < importer.ast.files.size(); i++) {
			StdumpAST.SourceFile sourceFile = (StdumpAST.SourceFile) importer.ast.files.get(i);
			for(StdumpAST.Node functionNode : sourceFile.functions) {
				StdumpAST.FunctionDefinition def = (StdumpAST.FunctionDefinition) functionNode;
				StdumpAST.FunctionType type = (StdumpAST.FunctionType) def.type;
				if(def.addressRange.valid()) {
					// Find or create the function.
					Address low = toAddr(def.addressRange.low);
					Address high = toAddr(def.addressRange.high - 1);
					AddressSet range = new AddressSet(low, high);
					Function function = findOrCreateFunction(def, low, high, range);
					if(function == null) {
						continue;
					}
					setFunctionName(function, def);
					function.setComment(sourceFile.path);
					importer.currentFuncOrGlobalName = def.name;
					if(type.returnType != null) {
						try {
							importer.stage = StdumpAST.ImportStage.RETURN_TYPE;
							function.setReturnType(type.returnType.createType(importer), SourceType.ANALYSIS);
						} catch (InvalidInputException e) {
							log.appendException(e);
						}
					}
					importer.stage = StdumpAST.ImportStage.PARAMETERS;
					HashSet<String> parameterNames = fillInParameters(function, importer, def, type);
					if(importer.outputLineNumbers) {
						for(StdumpAST.LineNumberPair pair : def.lineNumbers) {
							setEOLComment(toAddr(pair.address), "Line " + Integer.toString(pair.lineNumber));
						}
					}
					if(importer.markInlinedCode) {
						markInlinedCode(def, sourceFile);
					}
					importer.stage = StdumpAST.ImportStage.LOCAL_VARIABLES;
					fillInLocalVariables(function, importer, def, parameterNames);
				}
			}
			
			monitor.setProgress(i);
		}
	}
	
	public void removeJunkLabels(Program program) {
		final String JUNK_LABELS[] = {
				"__gnu_compiled_c",
				"__gnu_compiled_cplusplus",
				"gcc2_compiled."
		};
		
		SymbolTable symbolTable = program.getSymbolTable();
		for(String junkLabel : JUNK_LABELS) {
			SymbolIterator iterator = symbolTable.getSymbols(junkLabel);
			while(iterator.hasNext()) {
				symbolTable.removeSymbolSpecial(iterator.next());
			}
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
	
	private void setFunctionName(Function function, StdumpAST.FunctionDefinition def) {
		try {
			function.setName(def.name, SourceType.ANALYSIS);
		} catch (InvalidInputException e) {
			log.appendException(e);
		} catch (DuplicateNameException e) {}
	}
	
	private HashSet<String> fillInParameters(Function function, StdumpAST.ImporterState importer,
			StdumpAST.FunctionDefinition def, StdumpAST.FunctionType type) {
		HashSet<String> parameterNames = new HashSet<>();
		if(type.parameters.size() > 0) {
			ArrayList<Variable> parameters = new ArrayList<>();
			for(int i = 0; i < type.parameters.size(); i++) {
				StdumpAST.Variable variable = (StdumpAST.Variable) type.parameters.get(i);
				importer.currentVariableName = variable.name;
				DataType parameterType = StdumpAST.replaceVoidWithUndefined1(variable.type.createType(importer));
				if(variable.storage.isByReference) {
					parameterType = new PointerDataType(parameterType);
				}
				try {
					parameters.add(new ParameterImpl(variable.name, parameterType, program));
				} catch (InvalidInputException e) {
					log.appendException(e);
				}
				parameterNames.add(variable.name);
			}
			try {
				function.replaceParameters(parameters, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
			} catch(DuplicateNameException | InvalidInputException exception) {
				log.appendMsg("Failed to setup parameters for " + def.name + ": " + exception.getMessage());
			}
		}
		return parameterNames;
	}
	
	private void markInlinedCode(StdumpAST.FunctionDefinition def, StdumpAST.SourceFile sourceFile) {
		String path;
		if(def.relativePath != null) {
			path = def.relativePath;
		} else {
			path = sourceFile.relativePath;
		}
		String lastPath = "";
		for(StdumpAST.SubSourceFile sub : def.subSourceFiles) {
			if(!sub.relativePath.equals(lastPath) && sub.address >= def.addressRange.low && sub.address < def.addressRange.high) {
				if(!sub.relativePath.equals(path)) {
					setPreComment(toAddr(sub.address), "inlined from " + sub.relativePath);
				} else {
					setPreComment(toAddr(sub.address), "end of inlined section");
				}
			}
			lastPath = sub.relativePath;
		}
	}
	
	private void fillInLocalVariables(Function function, StdumpAST.ImporterState importer,
			StdumpAST.FunctionDefinition def, HashSet<String> parameterNames) {
		// Add local variables.
		HashMap<String, StdumpAST.Variable> stackLocals = new HashMap<>();
		for(StdumpAST.Node child : def.locals) {
			if(child instanceof StdumpAST.Variable && !parameterNames.contains(child.name)) {
				StdumpAST.Variable src = (StdumpAST.Variable) child;
				if(src.storageClass != StdumpAST.StorageClass.STATIC && src.storage.type == StdumpAST.VariableStorageType.STACK) {
					stackLocals.put(src.name, src);
				}
			}
		}
		for(Map.Entry<String, StdumpAST.Variable> local : stackLocals.entrySet()) {
			StdumpAST.Variable var = local.getValue();
			importer.currentVariableName = var.name;
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
		importer.stage = StdumpAST.ImportStage.GLOBAL_VARIABLES;
		
		monitor.setMessage("STABS - Importing global variables...");
		monitor.setMaximum(importer.ast.files.size());
		monitor.setProgress(0);
		
		AddressSpace space = getAddressFactory().getDefaultAddressSpace();
		for(int i = 0; i < importer.ast.files.size(); i++) {
			StdumpAST.SourceFile file = (StdumpAST.SourceFile) importer.ast.files.get(i);
			for(StdumpAST.Node global_node : file.globals) {
				StdumpAST.Variable global = (StdumpAST.Variable) global_node;
				if(global.storage.globalAddress > -1) {
					importer.currentFuncOrGlobalName = global.name;
					DataType type = StdumpAST.replaceVoidWithUndefined1(global.type.createType(importer));
					Address address = space.getAddress(global.storage.globalAddress);
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
	
	public static byte[] runStdump(String elfPath, TaskMonitor monitor, MessageLog log) throws InterruptedException, IOException {
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
		byte[] output = stdout.readAllBytes();
		while(errorReader.ready()) {
			log.appendMsg("STABS", stripColourCodes(errorReader.readLine()));
		}
		int returnCode = process.waitFor();
		if(returnCode == 0) {
			return output;
		} else {
			return null;
		}
		
	}
	
	public static String stripColourCodes(String input) {
		StringBuilder output = new StringBuilder();
		for(int i = 0; i < input.length(); i++) {
			if(i + 1 < input.length() && input.charAt(i) == '\033' && input.charAt(i + 1) == '[') {
				if(i + 3 < input.length() && input.charAt(i + 3) == 'm') {
					i += 3;
				} else {
					i += 4;
				}
			} else {
				output.append(input.charAt(i));
			}
		}
		return output.toString();
	}
	
	public final static DataTypeConflictHandler STABS_DATA_TYPE_CONFLICT_HANDLER = new DataTypeConflictHandler() {
		@Override
		public ConflictResult resolveConflict(DataType addedDataType, DataType existingDataType) {
			// If we're trying to make a typedef to built-in with the same name
			// as said built-in, just use the built-in itself instead so we
			// don't create a ".conflict" type.
			boolean typedefAndBuiltIn = addedDataType instanceof TypedefDataType && existingDataType instanceof BuiltInDataType;
			boolean sizesEqual = addedDataType.getLength() == existingDataType.getLength();
			if(typedefAndBuiltIn && sizesEqual) {
				return ConflictResult.USE_EXISTING;
			}
			
			return ConflictResult.RENAME_AND_ADD;
		}

		@Override
		public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
			return true;
		}

		@Override
		public DataTypeConflictHandler getSubsequentHandler() {
			return DataTypeConflictHandler.DEFAULT_HANDLER;
		}
	};
}
