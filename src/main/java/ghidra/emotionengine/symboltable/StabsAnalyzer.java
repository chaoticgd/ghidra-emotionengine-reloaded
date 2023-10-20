package ghidra.emotionengine.symboltable;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class StabsAnalyzer extends AbstractAnalyzer {
	
	public static final String STABS_ANALYZER_NAME = "STABS";
	public static final String STABS_ANALYZER_DESCRIPTION =
			"Parses STABS symbols from the .mdebug section to extract" +
			" information about data types, functions and global variables." +
			" Most of this process is handled by stdump, a C++ program which is" +
			" bundled with releases of Ghidra Emotion Engine: Reloaded. If this" +
			" file is missing, download stdump " + StdumpParser.SUPPORTED_STDUMP_VERSION +
			" from the link below, and put it in the" +
			" ghidra-emotionengine-reloaded/os directory (see further" +
			" instructions there).\n\n" +
			"For more information see:\n" +
			"https://github.com/chaoticgd/ccc";
	
	public static final String OPTION_EMBED_BASE_CLASSES = "Embed Base Classes";
	public static final String OPTION_EMBED_BASE_CLASSES_DESC =
			"Embed fields from base classes in sub classes so that the type of the vtable pointer can be set correctly.";
	
	public static final String OPTION_IMPORT_BUILTINS = "Import Built-in Types";
	public static final String OPTION_IMPORT_BUILTINS_DESC =
			"Create typedefs for built-in types instead of using their Ghidra equivalents (e.g. use 'unsigned char' instead of 'uchar').";
	
	public static final String OPTION_IMPORT_FUNCTIONS = "Import Functions";
	public static final String OPTION_IMPORT_FUNCTIONS_DESC =
			"Import functions from the symbol table into Ghidra.";
	
	public static final String OPTION_IMPORT_GLOBALS = "Import Global Variables";
	public static final String OPTION_IMPORT_GLOBALS_DESC =
			"Import global variables from the STABS symbols into Ghidra.";
	
	public static final String OPTION_IMPORT_TYPEDEFS = "Import Typedefs";
	public static final String OPTION_IMPORT_TYPEDEFS_DESC =
			"Import typedefs instead of using their underlying types.";
	
	public static final String OPTION_INLINED_CODE = "Mark Inlined Code";
	public static final String OPTION_INLINED_CODE_DESC =
			"Mark inlined code using pre comments.";
	
	public static final String OPTION_LINE_NUMBERS = "Output Line Numbers";
	public static final String OPTION_LINE_NUMBERS_DESC =
			"Output source line numbers as end-of-line comments that will appear in the diassembly.";
	
	public static final String OPTION_ONLY_RUN_ONCE = "Only Run Once";
	public static final String OPTION_ONLY_RUN_ONCE_DESC =
			"Bail out if over 50% of the recovered types already exist to prevent the user from accidentally corrupting their file.";
	
	public static final String OPTION_OVERRIDE_ELF_PATH = "Override ELF Path (Optional)";
	public static final String OPTION_OVERRIDE_ELF_PATH_DESC =
			"Use an ELF file of your choice as input to stdump instead of the currently loaded program.";
	
	public static final String OPTION_OVERRIDE_JSON_PATH = "Override JSON Path (Optional)";
	public static final String OPTION_OVERRIDE_JSON_PATH_DESC =
			"Parse a JSON file of your choice instead of running stdump and using its output.";
	
	private StabsImporter.ImportOptions importOptions = new StabsImporter.ImportOptions();
	private StabsImporter.ImportOptions DEFAULT_OPTIONS = new StabsImporter.ImportOptions();
	StabsImporter importer = null;
	
	public StabsAnalyzer() {
		super(STABS_ANALYZER_NAME, STABS_ANALYZER_DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
	}
	
	@Override
	public boolean getDefaultEnablement(Program program) {
		MemoryBlock section = program.getMemory().getBlock(".mdebug");
		return section != null;
	}
	
	@Override
	public boolean canAnalyze(Program program) {
		Language language = program.getLanguage();
		String id = language.getLanguageID().getIdAsString().toLowerCase();
		return id.startsWith("mips") || id.startsWith("r5900");
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		importer = new StabsImporter(program, importOptions, monitor, log);
		return importer.doImport();
	}
	
	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_EMBED_BASE_CLASSES, DEFAULT_OPTIONS.embedBaseClasses, null, OPTION_EMBED_BASE_CLASSES_DESC);
		options.registerOption(OPTION_IMPORT_BUILTINS, DEFAULT_OPTIONS.importBuiltins, null, OPTION_IMPORT_BUILTINS_DESC);
		options.registerOption(OPTION_IMPORT_FUNCTIONS, DEFAULT_OPTIONS.importFunctions, null, OPTION_IMPORT_FUNCTIONS_DESC);
		options.registerOption(OPTION_IMPORT_GLOBALS, DEFAULT_OPTIONS.importGlobals, null, OPTION_IMPORT_GLOBALS_DESC);
		options.registerOption(OPTION_IMPORT_TYPEDEFS, DEFAULT_OPTIONS.importTypedefs, null, OPTION_IMPORT_TYPEDEFS_DESC);
		options.registerOption(OPTION_INLINED_CODE, DEFAULT_OPTIONS.markInlinedCode, null, OPTION_INLINED_CODE_DESC);
		options.registerOption(OPTION_LINE_NUMBERS, DEFAULT_OPTIONS.outputLineNumbers, null, OPTION_LINE_NUMBERS_DESC);
		options.registerOption(OPTION_ONLY_RUN_ONCE, DEFAULT_OPTIONS.onlyRunOnce, null, OPTION_ONLY_RUN_ONCE_DESC);
		options.registerOption(OPTION_OVERRIDE_ELF_PATH, DEFAULT_OPTIONS.overrideElfPath, null, OPTION_OVERRIDE_ELF_PATH_DESC);
		options.registerOption(OPTION_OVERRIDE_JSON_PATH, DEFAULT_OPTIONS.overrideJsonPath, null, OPTION_OVERRIDE_JSON_PATH_DESC);
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		importOptions.embedBaseClasses = options.getBoolean(OPTION_EMBED_BASE_CLASSES, DEFAULT_OPTIONS.embedBaseClasses);
		importOptions.importBuiltins = options.getBoolean(OPTION_IMPORT_BUILTINS, DEFAULT_OPTIONS.importBuiltins);
		importOptions.importFunctions = options.getBoolean(OPTION_IMPORT_FUNCTIONS, DEFAULT_OPTIONS.importFunctions);
		importOptions.importGlobals = options.getBoolean(OPTION_IMPORT_GLOBALS, DEFAULT_OPTIONS.importGlobals);
		importOptions.importTypedefs = options.getBoolean(OPTION_IMPORT_TYPEDEFS, DEFAULT_OPTIONS.importTypedefs);
		importOptions.markInlinedCode = options.getBoolean(OPTION_INLINED_CODE, DEFAULT_OPTIONS.markInlinedCode);
		importOptions.outputLineNumbers = options.getBoolean(OPTION_LINE_NUMBERS, DEFAULT_OPTIONS.outputLineNumbers);
		importOptions.onlyRunOnce = options.getBoolean(OPTION_ONLY_RUN_ONCE, DEFAULT_OPTIONS.onlyRunOnce);
		importOptions.overrideElfPath = options.getString(OPTION_OVERRIDE_ELF_PATH, DEFAULT_OPTIONS.overrideElfPath);
		importOptions.overrideJsonPath = options.getString(OPTION_OVERRIDE_JSON_PATH, DEFAULT_OPTIONS.overrideJsonPath);
	}
	
}
