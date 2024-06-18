package com.github.manevolent.atlas.logic.subaru;

import com.github.manevolent.atlas.logic.TableFunction;
import com.github.manevolent.atlas.logic.TableInspector;
import com.github.manevolent.atlas.logic.TablePlan;
import ghidra.app.emulator.Emulator;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.emulator.MemoryAccessFilter;
import ghidra.pcode.emulate.EmulateExecutionState;

import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.FunctionPrototype;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.stream.IntStream;

/**
 * Models after the Subaru DI OS code for computing tables
 */
public class SubaruDITableFunction implements TableFunction {
    private final SubaruDIOS os;
    private final Program program;
    private final Address functionAddress;
    private final Register returnRegister;

    private final Register[] arguments;

    public SubaruDITableFunction(SubaruDIOS os, Program program, FunctionPrototype prototype, Address functionAddress) {
        this.os = os;
        this.program = program;
        this.functionAddress = functionAddress;
        this.returnRegister = prototype.getReturnStorage().getRegister();

        this.arguments = IntStream.range(0, prototype.getNumParams())
                .mapToObj(prototype::getParam)
                .map(p -> p.getStorage().getRegister())
                .toArray(Register[]::new);
    }

    @Override
    public SubaruDIOS getOS() {
        return os;
    }

    @Override
    public long getOffset() {
        return functionAddress.getOffset();
    }

    @Override
    public int getDimensions() {
        return arguments.length - 1;
    }

    @Override
    public TableInspector createInspector() {
        return switch (getDimensions()) {
            case 1 -> new SubaruDITableInspector1D(this);
            case 2 -> new SubaruDITableInspector2D(this);
            default -> throw new UnsupportedOperationException("unsupported dimension count: " + getDimensions());
        };
    }

    protected Emulator newEmulator(long structureAddress, int... coordinates) {
        Emulator emulator = new EmulatorHelper(program).getEmulator();
        MemoryState state = emulator.getMemState();

        // Set the table struct offset
        state.setValue(arguments[0], structureAddress);

        // Set X,Y
        for (int i = 0; i < coordinates.length; i ++) {
            int coordinateValue = coordinates[i];
            state.setValue(arguments[i + 1], coordinateValue);
        }

        emulator.setExecuteAddress(functionAddress.getOffset());

        return emulator;
    }

    public float emulate(SubaruDITableInspector inspector, int... coordinates) {
        return emulate(SubaruDITableInspector.root, inspector, coordinates);
    }

    public float emulate(long structureAddress, MemoryAccessFilter filter, int... coordinates) {
        int dimensions = getDimensions();
        if (coordinates.length != dimensions) {
            throw new IllegalArgumentException(String.format("%d != %d", coordinates.length, dimensions));
        }

        Emulator emulator = newEmulator(structureAddress, coordinates);

        try {
            if (filter != null) {
                emulator.addMemoryAccessFilter(filter);
            }

            // Execute
            while (emulator.getEmulateExecutionState() != EmulateExecutionState.FAULT
                    && emulator.getExecuteAddress().getOffset() != 0L) {
                try {
                    emulator.executeInstruction(true, TaskMonitor.DUMMY);
                } catch (CancelledException e) {
                    break;
                }
            }

            Register returnRegister = this.returnRegister;

            if (returnRegister == null) {
                //TODO: Assuming r10 is always the return value is probably a terrible idea... but no better ideas atm
                returnRegister = program.getRegister("r10");
            }

            // Extract return value
            return emulator.getMemState().getValue(returnRegister);
        } finally {
            emulator.dispose();
        }
    }

    @Override
    public float compute(long structureAddress, int... coordinates) {
        return emulate(structureAddress, null, coordinates);
    }

    @Override
    public String toString() {
        return "0x" + functionAddress.toString();
    }
}
