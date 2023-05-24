// Load a pcsx2 savestate into the writeable memory blocks.
//@category ghidra-emotionengine
import java.io.File;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.program.database.mem.MemoryBlockDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

public class PCSX2SaveStateImporter extends GhidraScript {

    private static final long MAX_ADDRESS = 0x10000000;
    private static final String MAIN_MEMORY = "eeMemory.bin";
    private static final String OTHER_BLOCK = ".other";
    private static final Map<String, String> PATHS = Map.of(
        "Scratchpad.bin", "scratchpad",
        "vu0Memory.bin", "vu0.data",
        "vu0MicroMem.bin", "vu0.code",
        "vu1Memory.bin", "vu1.data",
        "vu1MicroMem.bin", "vu1.code"
    );
    
    @Override
    public void run() throws Exception {
        FileSystemService fss = FileSystemService.getInstance();
        File file = askFile("Select a savestate", "open");
        FSRL fsrl = fss.getLocalFSRL(file);
        GFileSystem gfs = fss.openFileSystemContainer(fsrl, monitor);
        loadMainMemory(gfs);
        monitor.initialize(PATHS.size());
        monitor.setMessage("Loading Additional Memory...");
        for (String path : PATHS.keySet()) {
            monitor.checkCanceled();
            ByteBuffer buf = getBuffer(gfs, path);
            MemoryBlock block = getMemoryBlock(PATHS.get(path));
            if (block != null) {
                replaceBlock(block, buf);
            }
            monitor.incrementProgress(1);
        }
    }

    private ByteBuffer getBuffer(GFileSystem gfs, String path) throws Exception {
        GFile gFile = gfs.lookup(path);
        InputStream stream = gfs.getInputStream(gFile, monitor);
        ByteBuffer buf = ByteBuffer.wrap(stream.readAllBytes());
        buf.mark();
        return buf;
    }

    private void loadMainMemory(GFileSystem gfs) throws Exception {
        ByteBuffer buf = getBuffer(gfs, MAIN_MEMORY);
        MemoryBlock[] blocks = getMemoryBlocks();
        long maxAddress = 0;
        monitor.initialize(blocks.length);
        monitor.setMessage("Loading Main Memory...");
        for (MemoryBlock block : blocks) {
            monitor.checkCanceled();
            long end = block.getEnd().getOffset();
            if (end > maxAddress && end < MAX_ADDRESS && !block.isOverlay()) {
                maxAddress = block.getEnd().getOffset();
            }
            if (block.isWrite() && !block.isExecute()) {
                // only load and replace writable, non-executable memory blocks
                int offset = (int) block.getStart().getOffset();
                if (offset < buf.limit()) {
                    buf.position(offset);
                    replaceBlock(block, buf);
                }
            }
            monitor.incrementProgress(1);
        }
        Address otherAddress = toAddr(++maxAddress);
        buf.position((int) maxAddress);
        if (buf.hasRemaining()) {
            byte[] bytes = new byte[buf.remaining()];
            buf.get(bytes);
            MemoryBlock block = getMemoryBlock(OTHER_BLOCK);
            if (block == null) {
                block = createMemoryBlock(OTHER_BLOCK, otherAddress, bytes, false);
                block.setRead(true);
                block.setWrite(true);
            }
        }
    }

    private void replaceBlock(MemoryBlock block, ByteBuffer buf) throws Exception {
        byte[] bytes = new byte[(int) block.getSize()];
        buf.get(bytes);
        if (!block.isInitialized()) {
			block = currentProgram.getMemory().convertToInitialized(block, (byte) 0);
            block.setRead(true);
            block.setWrite(true);
        }
        block.putBytes(block.getStart(), bytes);
    }
}
