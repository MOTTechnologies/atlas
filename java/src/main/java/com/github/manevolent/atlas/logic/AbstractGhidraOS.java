package com.github.manevolent.atlas.logic;

import com.github.manevolent.atlas.logic.subaru.SubaruDITableExecution;
import com.github.manevolent.atlas.model.Calibration;
import db.Transaction;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerContextImpl;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.nio.ByteOrder;

/**
 * An abstract class that introduces the Ghidra API into the OS API chain
 */
public abstract class AbstractGhidraOS implements OS {

    /**
     * Disassembles one instruction from the given address.
     * @param disassembler disassembler instance.
     * @param address address to disassemble at.
     * @return disassembled instruction.
     */
    public static Instruction disassembleOne(Disassembler disassembler, Address address) {
        InstructionBlock block = disassembler.pseudoDisassembleBlock(address,
                new RegisterValue(Register.NO_CONTEXT), 1);
        if (block == null) {
            return null;
        }

        return block.getInstructionAt(address);
    }

    /**
     * I figure this would always be Sleigh, but if you need another language, see alternative constructors below.
     * @return the default system language provider.
     */
    protected static LanguageProvider getLanguageProvider() {
        return SleighLanguageProvider.getSleighLanguageProvider();
    }

    private final Calibration calibration;
    private final Language language;
    private final Program program;

    private final ThreadLocal<WeakReference<Disassembler>> disassembler = new ThreadLocal<>();

    protected AbstractGhidraOS(Calibration calibration, String languageId) throws IOException {
        this(calibration, new LanguageID(languageId));
    }

    protected AbstractGhidraOS(Calibration calibration, LanguageID languageId) throws IOException {
        this(calibration, getLanguageProvider().getLanguage(languageId));
    }

    protected AbstractGhidraOS(Calibration calibration, Language language) throws IOException {
        this.calibration = calibration;
        this.language = language;

        // Create the program instance using default logic
        this.program = createProgram(calibration);
    }

    /**
     * For constructing an AbstractGhidraOS when you want to define your own program object.
     * @param calibration calibration.
     * @param program program corresponding to the calibration provided.
     * @throws IOException
     */
    protected AbstractGhidraOS(Calibration calibration, Program program) throws IOException {
        this.calibration = calibration;
        this.program = program;
        this.language = program.getLanguage();
    }

    @Override
    public Calibration getCalibration() {
        return calibration;
    }

    public Program getProgram() {
        return program;
    }

    public Language getLanguage() {
        return language;
    }

    protected AddressSpace getDefaultAddressSpace(Program program) {
        return program.getAddressFactory().getAddressSpace("ram");
    }

    public Address getAddress(long offset) {
        return getDefaultAddressSpace(getProgram()).getAddressInThisSpaceOnly(offset);
    }

    private Disassembler newDisassembler() {
        Disassembler disassembler = Disassembler.getDisassembler(getProgram(),
                TaskMonitor.DUMMY, DisassemblerMessageListener.IGNORE);

        disassembler.setSeedContext(new DisassemblerContextImpl(program.getProgramContext()));

        return disassembler;
    }

    public Disassembler getDisassembler() {
        Disassembler disassembler;
        WeakReference<Disassembler> reference;
        reference = this.disassembler.get();
        if (reference == null || (disassembler = reference.get()) == null) {
            disassembler = newDisassembler();
            reference = new WeakReference<>(disassembler);
            this.disassembler.set(reference);
        }
        disassembler.resetDisassemblerContext();
        return disassembler;
    }

    protected MemoryBlock createMemoryBlock(Program program, AddressSpace addressSpace) throws IOException {
        MemoryBlock block;

        try {
            block = program.getMemory().createInitializedBlock(
                    calibration.getName(),
                    addressSpace.getAddress(calibration.getBaseAddress()),
                    (long) calibration.getLength(),
                    (byte) 0x00,
                    TaskMonitor.DUMMY,
                    false);
        } catch (LockException | MemoryConflictException | AddressOverflowException | CancelledException e) {
            throw new RuntimeException(e);
        }

        try {
            block.putBytes(block.getStart(), calibration.readFully());
        } catch (MemoryAccessException e) {
            throw new RuntimeException(e);
        }

        return block;
    }

    /**
     * Gets a Ghidra program from an input Calibration instance.
     * @param calibration calibration to create a program for.
     * @return Program instance.
     */
    protected Program createProgram(Calibration calibration) throws IOException {
        ProgramDB program = new ProgramDB(
                calibration.getName(),
                getLanguage(),
                getLanguage().getDefaultCompilerSpec(),
                calibration);

        AddressSpace addressSpace = getDefaultAddressSpace(program);

        try (Transaction t = program.openTransaction("new block")) {
            createMemoryBlock(program, addressSpace);
        }

        return program;
    }

    public ByteOrder getByteOrder() {
        return getLanguage().isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
    }
}
