package ghidra.emotionengine.symboltable;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.stream.JsonReader;

public class StdumpParser {
	public static final String SUPPORTED_STDUMP_VERSION = "v1.0";
	public static final int SUPPORTED_FORMAT_VERSION = 7;
	
	public static StdumpAST.ParsedJsonFile readJson(byte[] json) throws FileNotFoundException {
		JsonReader reader = new JsonReader(new InputStreamReader(new ByteArrayInputStream(json)));
		GsonBuilder gsonBuilder = new GsonBuilder();
		gsonBuilder.registerTypeAdapter(StdumpAST.ParsedJsonFile.class, new JsonFileDeserializer());
		gsonBuilder.registerTypeAdapter(StdumpAST.Node.class, new NodeDeserializer());
		Gson gson = gsonBuilder.create();
		return gson.fromJson(reader, StdumpAST.ParsedJsonFile.class);
	}
	
	private static class JsonFileDeserializer implements JsonDeserializer<StdumpAST.ParsedJsonFile> {
		@Override
		public StdumpAST.ParsedJsonFile deserialize(JsonElement element, Type type, JsonDeserializationContext context)
				throws JsonParseException {
			StdumpAST.ParsedJsonFile result = new StdumpAST.ParsedJsonFile();
			JsonObject object = element.getAsJsonObject();
			if(!object.has("version")) {
				throw new JsonParseException("JSON file has missing version number field.");
			}
			int version = object.get("version").getAsInt();
			if(version != SUPPORTED_FORMAT_VERSION) {
				String versionInfo = Integer.toString(version) + ", should be " + Integer.toString(SUPPORTED_FORMAT_VERSION);
				throw new JsonParseException("JSON file is in an unsupported format (version is " + versionInfo + "). You're probably using the wrong version of stdump!");
			}
			JsonArray files = object.get("files").getAsJsonArray();
			for(JsonElement fileNode : files) {
				result.files.add(context.deserialize(fileNode, StdumpAST.Node.class));
			}
			JsonArray deduplicatedTypes = object.get("deduplicated_types").getAsJsonArray();
			for(JsonElement type_node : deduplicatedTypes) {
				result.deduplicatedTypes.add(context.deserialize(type_node, StdumpAST.Node.class));
			}
			return result;
		}
	}
	
	private static class NodeDeserializer implements JsonDeserializer<StdumpAST.Node> {
		@Override
		public StdumpAST.Node deserialize(JsonElement element, Type type, JsonDeserializationContext context)
				throws JsonParseException {
			JsonObject object = element.getAsJsonObject();
			String descriptor = object.get("descriptor").getAsString();
			StdumpAST.Node node;
			if(descriptor.equals("array")) {
				StdumpAST.Array array = new StdumpAST.Array();
				array.element_type = context.deserialize(object.get("element_type"), StdumpAST.Node.class);
				array.element_count = object.get("element_count").getAsInt();
				node = array;
			} else if(descriptor.equals("bitfield")) {
				StdumpAST.BitField bitfield = new StdumpAST.BitField();
				bitfield.underlying_type = context.deserialize(object.get("underlying_type"), StdumpAST.Node.class);
				node = bitfield;
			} else if(descriptor.equals("builtin")) {
				StdumpAST.BuiltIn builtin = new StdumpAST.BuiltIn();
				String builtin_class = object.get("class").getAsString();
				builtin.builtin_class = readBuiltInClass(builtin, builtin_class);
				node = builtin;
			} else if(descriptor.equals("function_definition")) {
				StdumpAST.FunctionDefinition function = new StdumpAST.FunctionDefinition();
				if(object.has("address_range")) {
					function.addressRange = readAddressRange(object.get("address_range").getAsJsonObject());
				}
				if(object.has("relative_path")) {
					function.relativePath = object.get("relative_path").getAsString();
				}
				function.type = context.deserialize(object.get("type"), StdumpAST.Node.class);
				for(JsonElement local : object.get("locals").getAsJsonArray()) {
					function.locals.add(context.deserialize(local.getAsJsonObject(), StdumpAST.Node.class));
				}
				for(JsonElement pair : object.get("line_numbers").getAsJsonArray()) {
					JsonArray src = pair.getAsJsonArray();
					StdumpAST.LineNumberPair dest = new StdumpAST.LineNumberPair();
					dest.address = src.get(0).getAsInt();
					dest.lineNumber = src.get(1).getAsInt();
					function.lineNumbers.add(dest);
				}
				for(JsonElement sub : object.get("sub_source_files").getAsJsonArray()) {
					JsonObject src = sub.getAsJsonObject();
					StdumpAST.SubSourceFile dest = new StdumpAST.SubSourceFile();
					dest.address = src.get("address").getAsInt();
					dest.relativePath = src.get("path").getAsString();
					function.subSourceFiles.add(dest);
				}
				node = function;
			} else if(descriptor.equals("function_type")) {
				StdumpAST.FunctionType function_type = new StdumpAST.FunctionType();
				if(object.has("return_type")) {
					function_type.returnType = context.deserialize(object.get("return_type"), StdumpAST.Node.class);
				}
				if(object.has("parameters")) {
					for(JsonElement parameter : object.get("parameters").getAsJsonArray()) {
						function_type.parameters.add(context.deserialize(parameter, StdumpAST.Node.class));
					}
				}
				function_type.vtableIndex = object.get("vtable_index").getAsInt();
				node = function_type;
			} else if(descriptor.equals("enum")) {
				StdumpAST.InlineEnum inline_enum = new StdumpAST.InlineEnum();
				for(JsonElement src : object.get("constants").getAsJsonArray()) {
					StdumpAST.EnumConstant dest = new StdumpAST.EnumConstant();
					JsonObject src_object = src.getAsJsonObject();
					dest.value = src_object.get("value").getAsInt();
					dest.name = src_object.get("name").getAsString();
					inline_enum.constants.add(dest);
				}
				node = inline_enum;
			} else if(descriptor.equals("struct") || descriptor.equals("union")) {
				StdumpAST.InlineStructOrUnion struct_or_union = new StdumpAST.InlineStructOrUnion();
				struct_or_union.isStruct = descriptor.equals("struct");
				if(struct_or_union.isStruct) {
					for(JsonElement base_class : object.get("base_classes").getAsJsonArray()) {
						struct_or_union.baseClasses.add(context.deserialize(base_class, StdumpAST.Node.class));
					}
				}
				for(JsonElement field : object.get("fields").getAsJsonArray()) {
					struct_or_union.fields.add(context.deserialize(field, StdumpAST.Node.class));
				}
				for(JsonElement member_function : object.get("member_functions").getAsJsonArray()) {
					struct_or_union.memberFunctions.add(context.deserialize(member_function, StdumpAST.Node.class));
				}
				node = struct_or_union;
			} else if(descriptor.equals("pointer")) {
				StdumpAST.Pointer pointer = new StdumpAST.Pointer();
				pointer.valueType = context.deserialize(object.get("value_type"), StdumpAST.Node.class);
				node = pointer;
			} else if(descriptor.equals("pointer_to_data_member")) {
				node = new StdumpAST.PointerToDataMember();
			} else if(descriptor.equals("reference")) {
				StdumpAST.Reference reference = new StdumpAST.Reference();
				reference.valueType = context.deserialize(object.get("value_type"), StdumpAST.Node.class);
				node = reference;
			} else if(descriptor.equals("source_file")) {
				StdumpAST.SourceFile source_file = new StdumpAST.SourceFile();
				source_file.path = object.get("path").getAsString();
				source_file.relativePath = object.get("relative_path").getAsString();
				source_file.text_address = object.get("text_address").getAsInt();
				for(JsonElement type_object : object.get("types").getAsJsonArray()) {
					source_file.types.add(context.deserialize(type_object, StdumpAST.Node.class));
				}
				for(JsonElement function_object : object.get("functions").getAsJsonArray()) {
					source_file.functions.add(context.deserialize(function_object, StdumpAST.Node.class));
				}
				for(JsonElement global_object : object.get("globals").getAsJsonArray()) {
					source_file.globals.add(context.deserialize(global_object, StdumpAST.Node.class));
				}
				JsonElement stabs_type_number_to_deduplicated_type_index = object.get("stabs_type_number_to_deduplicated_type_index");
				for(Map.Entry<String, JsonElement> entry : stabs_type_number_to_deduplicated_type_index.getAsJsonObject().entrySet()) {
					int stabs_type_number = Integer.parseInt(entry.getKey());
					int type_index = entry.getValue().getAsInt();
					source_file.stabsTypeNumberToDeduplicatedTypeIndex.put(stabs_type_number, type_index);
				}
				node = source_file;
			} else if(descriptor.equals("type_name")) {
				StdumpAST.TypeName type_name = new StdumpAST.TypeName();
				type_name.type_name = object.get("type_name").getAsString();
				if(object.has("referenced_file_index")) {
					type_name.referencedFileIndex = object.get("referenced_file_index").getAsInt();
				}
				if(object.has("referenced_stabs_type_number")) {
					type_name.referencedStabsTypeNumber = object.get("referenced_stabs_type_number").getAsInt();
				}
				node = type_name;
			} else if(descriptor.equals("variable")) {
				StdumpAST.Variable variable = new StdumpAST.Variable();
				String variable_class = object.get("class").getAsString();
				if(variable_class.equals("global")) {
					variable.variable_class = StdumpAST.VariableClass.GLOBAL;
				} else if(variable_class.equals("local")) {
					variable.variable_class = StdumpAST.VariableClass.LOCAL;
				} else if(variable_class.equals("parameter")) {
					variable.variable_class = StdumpAST.VariableClass.PARAMETER;
				} else {
					throw new JsonParseException("Bad variable class: " + variable_class);
				}
				variable.storage = readVariableStorage(object.get("storage").getAsJsonObject());
				if(object.has("block_low")) {
					variable.blockLow = object.get("block_low").getAsInt();
				}
				if(object.has("block_high")) {
					variable.blockHigh = object.get("block_high").getAsInt();
				}
				variable.type = context.deserialize(object.get("type"), StdumpAST.Node.class);
				node = variable;
			} else {
				throw new JsonParseException("Bad node descriptor: " + descriptor);
			}
			readCommon(node, object);
			return node;
		}
		
		private void readCommon(StdumpAST.Node dest, JsonObject src) throws JsonParseException {
			if(src.has("name")) {
				dest.name = src.get("name").getAsString();
			}
			if(src.has("storage_class")) {
				String storage_class = src.get("storage_class").getAsString();
				if(storage_class.equals("typedef")) {
					dest.storageClass = StdumpAST.StorageClass.TYPEDEF;
				} else if(storage_class.equals("extern")) {
					dest.storageClass = StdumpAST.StorageClass.EXTERN;
				} else if(storage_class.equals("static")) {
					dest.storageClass = StdumpAST.StorageClass.STATIC;
				} else if(storage_class.equals("auto")) {
					dest.storageClass = StdumpAST.StorageClass.AUTO;
				} else if(storage_class.equals("register")) {
					dest.storageClass = StdumpAST.StorageClass.REGISTER;
				}
			}
			if(src.has("relative_offset_bytes")) {
				dest.relativeOffsetBytes = src.get("relative_offset_bytes").getAsInt();
			}
			if(src.has("absolute_offset_bytes")) {
				dest.absoluteOffsetBytes = src.get("absolute_offset_bytes").getAsInt();
			}
			if(src.has("bitfield_offset_bits")) {
				dest.bitfieldOffsetBits = src.get("bitfield_offset_bits").getAsInt();
			}
			if(src.has("size_bits")) {
				dest.sizeBits = src.get("size_bits").getAsInt();
			}
			if(src.has("files")) {
				dest.firstFile = src.get("files").getAsJsonArray().get(0).getAsInt();
			}
			if(src.has("conflict")) {
				dest.conflict = src.get("conflict").getAsBoolean();
			}
			if(src.has("stabs_type_number")) {
				dest.stabsTypeNumber = src.get("stabs_type_number").getAsInt();
			}
		}
		
		private StdumpAST.BuiltInClass readBuiltInClass(StdumpAST.BuiltIn builtin, String builtin_class) throws JsonParseException {
			if(builtin_class.equals("void")) { return StdumpAST.BuiltInClass.VOID; }
			else if(builtin_class.equals("8-bit unsigned integer")) { return StdumpAST.BuiltInClass.UNSIGNED_8; }
			else if(builtin_class.equals("8-bit signed integer")) { return StdumpAST.BuiltInClass.SIGNED_8; }
			else if(builtin_class.equals("8-bit integer")) { return StdumpAST.BuiltInClass.UNQUALIFIED_8; }
			else if(builtin_class.equals("8-bit boolean")) { return StdumpAST.BuiltInClass.BOOL_8; }
			else if(builtin_class.equals("16-bit unsigned integer")) { return StdumpAST.BuiltInClass.UNSIGNED_16; }
			else if(builtin_class.equals("16-bit signed integer")) { return StdumpAST.BuiltInClass.SIGNED_16; }
			else if(builtin_class.equals("32-bit unsigned integer")) { return StdumpAST.BuiltInClass.UNSIGNED_32; }
			else if(builtin_class.equals("32-bit signed integer")) { return StdumpAST.BuiltInClass.SIGNED_32; }
			else if(builtin_class.equals("32-bit floating point")) { return StdumpAST.BuiltInClass.FLOAT_32; }
			else if(builtin_class.equals("64-bit unsigned integer")) { return StdumpAST.BuiltInClass.UNSIGNED_64; }
			else if(builtin_class.equals("64-bit signed integer")) { return StdumpAST.BuiltInClass.SIGNED_64; }
			else if(builtin_class.equals("64-bit floating point")) { return StdumpAST.BuiltInClass.FLOAT_64; }
			else if(builtin_class.equals("128-bit unsigned integer")) { return StdumpAST.BuiltInClass.UNSIGNED_128; }
			else if(builtin_class.equals("128-bit signed integer")) { return StdumpAST.BuiltInClass.SIGNED_128; }
			else if(builtin_class.equals("128-bit integer")) { return StdumpAST.BuiltInClass.UNQUALIFIED_128; }
			else if(builtin_class.equals("128-bit floating point")) { return StdumpAST.BuiltInClass.FLOAT_128; }
			else { throw new JsonParseException("Bad builtin class."); }
		}
		
		private StdumpAST.VariableStorage readVariableStorage(JsonObject src) {
			StdumpAST.VariableStorage dest = new StdumpAST.VariableStorage();
			String type = src.get("type").getAsString();
			if(type.equals("global")) {
				dest.type = StdumpAST.VariableStorageType.GLOBAL;
				dest.global_address = src.get("global_address").getAsInt();
			} else if(type.equals("register")) {
				dest.type = StdumpAST.VariableStorageType.REGISTER;
				dest.register = src.get("register").getAsString();
				dest.registerClass = src.get("register_class").getAsString();
				dest.dbxRegisterNumber = src.get("dbx_register_number").getAsInt();
				dest.registerIndexRelative = src.get("register_index").getAsInt();
				dest.isByReference = src.get("is_by_reference").getAsBoolean();
			} else if(type.equals("stack")) {
				dest.type = StdumpAST.VariableStorageType.STACK;
				dest.stackPointerOffset = src.get("stack_offset").getAsInt();
			} else {
				throw new JsonParseException("Bad variable storage type: " + type);
			}
			return dest;
		}
		
		private StdumpAST.AddressRange readAddressRange(JsonObject src) {
			StdumpAST.AddressRange dest = new StdumpAST.AddressRange();
			dest.low = src.get("low").getAsInt();
			dest.high = src.get("high").getAsInt();
			return dest;
		}
	}
	
}
