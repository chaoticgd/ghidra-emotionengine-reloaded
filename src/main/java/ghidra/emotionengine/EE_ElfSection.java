package ghidra.emotionengine;

import ghidra.program.model.data.CategoryPath;
import ghidra.util.task.TaskMonitor;

public interface EE_ElfSection {
	final CategoryPath ELF_PATH = new CategoryPath("/ELF");

	default void parse() throws Exception {
		parse(TaskMonitor.DUMMY);
	}

	void parse(TaskMonitor monitor) throws Exception;
}
