package ghidra.emotionengine.symboltable;

import java.util.ArrayList;
import java.util.HashMap;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.Integer16DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedInteger16DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.task.TaskMonitor;

public class StdumpAST {
	
	public static class ParsedJsonFile {
		ArrayList<Node> files = new ArrayList<Node>();
		ArrayList<Node> deduplicatedTypes = new ArrayList<Node>();
	}
	
	public static class ImporterState {
		// Options.
		boolean markInlinedCode = false;
		boolean outputLineNumbers = false;

		// Input.
		ParsedJsonFile ast;
		
		// Internal state.
		ArrayList<DataType> types = new ArrayList<>(); // (data type, size in bytes)
		ArrayList<HashMap<Integer, Integer>> stabsTypeNumberToDeduplicatedTypeIndex = new ArrayList<>();
		HashMap<String, Integer> typeNameToDeduplicatedTypeIndex = new HashMap<>();
		
		// Ghidra objects.
		TaskMonitor monitor;
		MessageLog log;
		DataTypeManager programTypeManager = null;
	}
	
	public static enum StorageClass {
		NONE,
		TYPEDEF,
		EXTERN,
		STATIC,
		AUTO,
		REGISTER
	}
	
	public static class AddressRange {
		int low = -1;
		int high = -1;
		
		public boolean valid() {
			return low > -1;
		}
	}
	
	public static class Node {
		String name;
		StorageClass storageClass = StorageClass.NONE;
		int relativeOffsetBytes = -1;
		int absoluteOffsetBytes = -1;
		int bitfieldOffsetBits = -1;
		int sizeBits = -1;
		int firstFile = -1;
		boolean conflict = false;
		int stabsTypeNumber = -1;
		
		String prefix = ""; // Used for nested structs.
		boolean isInCreateTypeCall = false; // Prevent infinite recursion.
		
		public DataType createType(ImporterState importer) {
			if(isInCreateTypeCall) {
				importer.log.appendMsg("STABS", "Bad circular type definition: " + name);
				return Undefined1DataType.dataType;
			}
			isInCreateTypeCall = true;
			DataType type = createTypeImpl(importer);
			isInCreateTypeCall = false;
			return type;
		}
		
		public DataType createTypeImpl(ImporterState importer) {
			importer.log.appendMsg("STABS", "createTypeImpl() called on a node that isn't a type.");
			return Undefined1DataType.dataType;
		}
		
		String generateName() {
			if(conflict || name == null || name.isEmpty()) {
				return prefix + name + "__" + Integer.toString(firstFile) + "_" + Integer.toString(stabsTypeNumber);
			}
			return name;
		}
	}
	
	public static class Array extends Node {
		Node element_type;
		int element_count;
		
		public DataType createTypeImpl(ImporterState importer) {
			DataType element = replaceVoidWithUndefined1(element_type.createType(importer));
			return new ArrayDataType(element, element_count, element.getLength());
		}
	}
	
	public static class BitField extends Node {
		Node underlying_type;
		
		public DataType createTypeImpl(ImporterState importer) {
			return underlying_type.createType(importer);
		}
	}
	
	public static enum BuiltInClass {
		VOID,
		UNSIGNED_8, SIGNED_8, UNQUALIFIED_8, BOOL_8,
		UNSIGNED_16, SIGNED_16,
		UNSIGNED_32, SIGNED_32, FLOAT_32,
		UNSIGNED_64, SIGNED_64, FLOAT_64,
		UNSIGNED_128, SIGNED_128, UNQUALIFIED_128, FLOAT_128,
		UNKNOWN_PROBABLY_ARRAY
	}
	
	public static class BuiltIn extends Node {
		BuiltInClass builtin_class;
		
		public DataType createTypeImpl(ImporterState importer) {
			switch(builtin_class) {
			case VOID:
				return VoidDataType.dataType;
			case UNSIGNED_8:
				return UnsignedCharDataType.dataType;
			case SIGNED_8:
			case UNQUALIFIED_8:
			case BOOL_8:
				return CharDataType.dataType;
			case UNSIGNED_16:
				return ShortDataType.dataType;
			case SIGNED_16:
				return UnsignedShortDataType.dataType;
			case UNSIGNED_32:
				return UnsignedIntegerDataType.dataType;
			case SIGNED_32:
				return IntegerDataType.dataType;
			case FLOAT_32:
				return FloatDataType.dataType;
			case UNSIGNED_64:
				return UnsignedLongDataType.dataType;
			case SIGNED_64:
			case FLOAT_64:
				return LongDataType.dataType;
			case UNSIGNED_128:
				return UnsignedInteger16DataType.dataType;
			case SIGNED_128:
				return Integer16DataType.dataType;
			case UNQUALIFIED_128:
			case FLOAT_128:
				return UnsignedInteger16DataType.dataType;
			case UNKNOWN_PROBABLY_ARRAY:
			}
			importer.log.appendMsg("STABS", "Bad builtin type created.");
			return Undefined1DataType.dataType;
		}
	}
	
	public static class LineNumberPair {
		int address;
		int lineNumber;
	}
	
	public static class SubSourceFile {
		int address;
		String relativePath;
	}
	
	public static class FunctionDefinition extends Node {
		AddressRange addressRange = new AddressRange();
		String relativePath;
		Node type;
		ArrayList<Variable> locals = new ArrayList<>();
		ArrayList<LineNumberPair> lineNumbers = new ArrayList<>();
		ArrayList<SubSourceFile> subSourceFiles = new ArrayList<>();
	}
	
	public static class FunctionType extends Node {
		Node returnType = null;
		ArrayList<Node> parameters = new ArrayList<Node>();
		int vtableIndex = -1;
		
		public DataType createTypeImpl(ImporterState importer) {
			return Undefined1DataType.dataType;
		}
	}
	
	public static class EnumConstant {
		int value;
		String name;
	}
	
	public static class InlineEnum extends Node {
		ArrayList<EnumConstant> constants = new ArrayList<EnumConstant>();
		
		public DataType createTypeImpl(ImporterState importer) {
			EnumDataType type = new EnumDataType(generateName(), 4);
			for(EnumConstant constant : constants) {
				type.add(constant.name, constant.value);
			}
			return type;
		}
	}
	
	public static class BaseClass {
		int offset;
		Node type;
	}
	
	public static class InlineStructOrUnion extends Node {
		boolean isStruct;
		ArrayList<BaseClass> baseClasses = new ArrayList<BaseClass>();
		ArrayList<Node> fields = new ArrayList<Node>();
		ArrayList<Node> memberFunctions = new ArrayList<Node>();
		
		public DataType createTypeImpl(ImporterState importer) {
			DataType result = create_empty(importer);
			fill(result, importer);
			return result;
		}
		
		public DataType create_empty(ImporterState importer) {
			String typeName = generateName();
			int sizeBytes = sizeBits / 8;
			DataType type;
			if(isStruct) {
				type = new StructureDataType(typeName, sizeBytes, importer.programTypeManager);
			} else {
				type = new UnionDataType(typeName);
			}
			return type;
		}
		
		public void fill(DataType dest, ImporterState importer) {
			if(isStruct) {
				Structure type = (Structure) dest;
				for(int i = 0; i < baseClasses.size(); i++) {
					BaseClass baseClass = baseClasses.get(i);
					DataType baseType = replaceVoidWithUndefined1(baseClass.type.createType(importer));
					boolean isBeyondEnd = baseClass.offset + baseType.getLength() > sizeBits / 8;
					if(!isBeyondEnd && baseClass.offset > -1) {
						type.replaceAtOffset(baseClass.offset, baseType, baseType.getLength(), "base_class_" + Integer.toString(i), "");
					}
				}
				for(Node node : fields) {
					if(node.storageClass != StorageClass.STATIC) {
						// Currently we don't try to import bit fields.
						boolean isBitfield = node instanceof BitField;
						DataType field = null;
						if(node.name != null && node.name.equals("__vtable")) {
							field = new PointerDataType(create_vtable(importer));
						} else {
							node.prefix += name + "__";
							field = replaceVoidWithUndefined1(node.createType(importer));
						}
						boolean isBeyondEnd = node.relativeOffsetBytes + field.getLength() > sizeBits / 8;
						if(!isBitfield && !isBeyondEnd) {
							type.replaceAtOffset(node.relativeOffsetBytes, field, field.getLength(), node.name, "");
						}
					}
				}
			} else {
				Union type = (Union) dest;
				for(Node node : fields) {
					if(node.storageClass != StorageClass.STATIC) {
						DataType field = replaceVoidWithUndefined1(node.createType(importer));
						type.add(field, field.getLength(), node.name, "");
					}
				}
			}
		}
		
		public DataType create_vtable(ImporterState importer) {
			StructureDataType vtable = new StructureDataType(generateName() + "__vtable", 0, importer.programTypeManager);
			for(Node node : memberFunctions) {
				if(node instanceof FunctionType) {
					FunctionType function = (FunctionType) node;
					if(function.vtableIndex > -1) {
						int end = (function.vtableIndex + 1) * 4;
						if(end > vtable.getLength()) {
							vtable.growStructure(end - vtable.getLength());
						}
						try {
							vtable.replaceAtOffset(function.vtableIndex * 4, PointerDataType.dataType, 4, function.name, "");
						} catch(IllegalArgumentException e) {}
					}
				}
			}
			return vtable;
		}
	}
	
	public static class Pointer extends Node {
		Node valueType;
		
		public DataType createTypeImpl(ImporterState importer) {
			return new PointerDataType(valueType.createType(importer));
		}
	}
	
	public static class PointerToDataMember extends Node {
		public DataType createTypeImpl(ImporterState importer) {
			return Undefined4DataType.dataType;
		}
	}
	
	public static class Reference extends Node {
		Node valueType;
		
		public DataType createTypeImpl(ImporterState importer) {
			return new PointerDataType(valueType.createType(importer));
		}
	}
	
	public static class SourceFile extends Node {
		String path;
		String relativePath;
		int text_address;
		ArrayList<Node> types = new ArrayList<Node>();
		ArrayList<Node> functions = new ArrayList<Node>();
		ArrayList<Node> globals = new ArrayList<Node>();
		HashMap<Integer, Integer> stabsTypeNumberToDeduplicatedTypeIndex = new HashMap<Integer, Integer>();
	}
	
	public static class TypeName extends Node {
		String type_name;
		int referencedFileIndex = -1;
		int referencedStabsTypeNumber = -1;
		
		public DataType createTypeImpl(ImporterState importer) {
			if(type_name.equals("void")) {
				return VoidDataType.dataType;
			}
			Integer index = null;
			if(referencedFileIndex > -1 && referencedStabsTypeNumber > -1) {
				// Lookup the type by its STABS type number. This path
				// ensures that the correct type is found even if multiple
				// types have the same name.
				HashMap<Integer, Integer> indexLookup = importer.stabsTypeNumberToDeduplicatedTypeIndex.get(referencedFileIndex);
				index = indexLookup.get(referencedStabsTypeNumber);
			}
			if(index == null) {
				// For STABS cross references, no type number is provided,
				// so we must lookup the type by name instead. This is
				// riskier but I think it's the best we can really do.
				index = importer.typeNameToDeduplicatedTypeIndex.get(type_name);
			}
			if(index == null) {
				importer.log.appendMsg("STABS", "Type lookup failed: " + type_name);
				return Undefined1DataType.dataType;
			}
			DataType type = importer.types.get(index);
			if(type == null) {
				Node node = importer.ast.deduplicatedTypes.get(index);
				if(node instanceof InlineStructOrUnion) {
					importer.log.appendMsg("STABS", "Bad type name referencing struct or union: " + type_name);
					return Undefined1DataType.dataType;
				}
				type = node.createType(importer);
				importer.types.set(index, type);
			}
			return type;
		}
	}
	
	public static enum VariableClass {
		GLOBAL,
		LOCAL,
		PARAMETER
	}
	
	public static enum VariableStorageType {
		GLOBAL,
		REGISTER,
		STACK
	}
	
	public static class VariableStorage {
		VariableStorageType type;
		int global_address = -1;
		String register;
		String registerClass;
		int dbxRegisterNumber = -1;
		int registerIndexRelative = -1;
		boolean isByReference = false;
		int stackPointerOffset = -1;
	}
	
	public static class Variable extends Node {
		VariableClass variable_class;
		VariableStorage storage;
		int blockLow = -1;
		int blockHigh = -1;
		Node type;
	}
	
	public static DataType replaceVoidWithUndefined1(DataType type) {
		if(type.isEquivalent(VoidDataType.dataType)) {
			return Undefined1DataType.dataType;
		}
		return type;
	}
	
}
