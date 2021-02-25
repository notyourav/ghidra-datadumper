import java.util.Iterator;
import java.util.ArrayList;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.mem.MemoryAccessException;
import java.io.File;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.io.PrintWriter;

public class CreateDecompDataset extends GhidraScript {

    final static int MAX_INSTR = 8000;
    private Address lastAddr = null;
    private Listing listing = null;
    private PseudoDisassembler disasm = null;
    private File saveFile;
    private ArrayList<String> csv = new ArrayList<>();

    @Override
    public void run() throws Exception {
	listing = currentProgram.getListing();
	saveFile = getSaveFile();
	disasm = new PseudoDisassembler(currentProgram);

	if (saveFile == null) {
	    println("Cancelling.");
	    return;
	}

	FunctionManager fm = currentProgram.getFunctionManager();
        DecompInterface decomplib = setUpDecompiler(currentProgram);
        try {
            if (!decomplib.openProgram(currentProgram)) {
        	println("Decompile Error: " + decomplib.getLastMessage());
        	return;
            }
	    for (Function fn : fm.getFunctions(true)) {
		decompileFunction(fn, decomplib);
		dumpFn();
		PrintWriter pw = new PrintWriter(saveFile);
		for (String s : csv) {
			pw.println(s);
	    	}
		pw.close();

		if (csv.size() > MAX_INSTR) {
		    break;
		}
	    }
        } finally {
            decomplib.dispose();
        }

        lastAddr = null;
    }

    private File getSaveFile() throws Exception {
	File file = askFile("Choose File Location", "Save");
	if (file.exists()) {
	    if (!askYesNo("File Already Exists", "A file already exists with the name you "
	      + "chose.\nDo you want to overwrite it?")) {
		return null;
	    }
	}
	return file;
    }

    private DecompInterface setUpDecompiler(Program program) {
	DecompInterface decomplib = new DecompInterface();

	DecompileOptions options;
	options = new DecompileOptions(); 
	OptionsService service = state.getTool().getService(OptionsService.class);
	if (service != null) {
	    ToolOptions opt = service.getOptions("Decompiler");
	    options.grabFromToolAndProgram(null,opt,program);    	
	}
        decomplib.setOptions(options);

	decomplib.toggleCCode(true);
	decomplib.toggleSyntaxTree(true);
	decomplib.setSimplificationStyle("decompile");

	return decomplib;
    }

    public void dumpFn() {
	// One option would be to disassemble everything in between
	// the function body's start and end, but this does not play
	// well with literal pools or functions that share code.
	// We can avoid this by capturing only what is inside the
	// decompiled basic blocks.
	ArrayList<Instruction> instructions = new ArrayList();
	ArrayList<PcodeBlockBasic> blocks = hfunction.getBasicBlocks();
	for (PcodeBlockBasic block : blocks) {
	    Address start = block.getStart();
	    Address stop = block.getStop();
	    AddressSet blockAddrs = new AddressSet(block.getStart(), block.getStop());

	    InstructionIterator iter = listing.getInstructions(blockAddrs, true);
	    for (Instruction i : iter) {
		InstructionContext ctx = i.getInstructionContext();
		InstructionPrototype proto = i.getPrototype();

		StringBuilder sb = new StringBuilder();
		sb.append(ctx.getAddress().toString() + ", ");
		sb.append(proto.getMnemonic(ctx) + ",");

		byte[] ibytes = new byte[proto.getLength()];
		ctx.getMemBuffer().getBytes(ibytes, 0);
		for (byte b : ibytes) {
		    sb.append(String.format(" %02x", b));
		}
		csv.add(sb.toString());
	    }
	}
    }

    HighFunction hfunction = null;
    ClangTokenGroup docroot = null;

    public boolean decompileFunction(Function f, DecompInterface decomplib) {
        DecompileResults decompRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), monitor);

        hfunction = decompRes.getHighFunction();
        docroot = decompRes.getCCodeMarkup();

        if (hfunction == null)
            return false;

        return true;
    }
}
