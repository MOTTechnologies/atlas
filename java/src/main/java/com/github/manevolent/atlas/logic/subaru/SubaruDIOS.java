package com.github.manevolent.atlas.logic.subaru;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.logic.*;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.ui.behavior.ProgressListener;
import com.github.manevolent.atlas.ui.util.Jobs;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;

import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;

import ghidra.program.model.lang.OperandType;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.util.UndefinedFunction;

import ghidra.util.task.TaskMonitor;
import org.checkerframework.checker.units.qual.A;

import javax.help.UnsupportedOperationException;
import java.io.IOException;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import java.util.logging.Level;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class SubaruDIOS extends AbstractGhidraOS {
    private static final String languageId = "v850e3:LE:32:default";

    private static final PropertyDefinition supportedDTCProperty = new PropertyDefinition(
            false,
            "subarudi.dtc.supportedAddress",
            "Supported DTC Address",
            "Address to the array of supported DTC",
            AddressProperty.class
    );

    private static final PropertyDefinition enabledDTCProperty = new PropertyDefinition(
            false,
            "subarudi.dtc.enabledAddress",
            "Enabled DTC Address",
            "Address to the array of enabled DTC",
            AddressProperty.class
    );

    public SubaruDIOS(Calibration calibration) throws IOException {
        super(calibration, languageId);
    }

    @Override
    public OSType getType() {
        return OSType.SUBARU_DI_RH850;
    }

    @Override
    public List<PropertyDefinition> getPropertyDefinitions() {
        return List.of(supportedDTCProperty, enabledDTCProperty);
    }

    @Override
    public List<SupportedDTC> getSupportedDTC() throws IOException {
        Calibration calibration = getCalibration();

        AddressProperty dtc_code_offset_property =
                getCalibration().getKeySet().getProperty(supportedDTCProperty.getKey(), AddressProperty.class);
        if (dtc_code_offset_property == null || dtc_code_offset_property.getAddress() <= 0L) {
            throw new UnsupportedOperationException("Calibration " + calibration.getName()
                    + " is missing property: " + supportedDTCProperty.getName());
        }
        long dtc_code_offset = dtc_code_offset_property.getAddress();

        AddressProperty dtc_enabled_offset_property =
                getCalibration().getKeySet().getProperty(enabledDTCProperty.getKey(), AddressProperty.class);
        if (dtc_enabled_offset_property == null || dtc_enabled_offset_property.getAddress() <= 0L) {
            throw new UnsupportedOperationException("Calibration " + calibration.getName()
                    + " is missing property: " + enabledDTCProperty.getName());
        }
        long dtc_enabled_offset = dtc_enabled_offset_property.getAddress();

        List<SupportedDTC> supportedDTCS = new ArrayList<>();
        int num_dtc = 0x67 * 8;
        BitReader bitReader = calibration.bitReader(dtc_code_offset);
        for (int index = 0; index < num_dtc; index ++) {
            int dtc_code = bitReader.readUShort() & 0xFFFF;
            dtc_code = Short.reverseBytes((short) dtc_code) & 0xFFFF;
            if (dtc_code == 0x0000) {
                // No reported code for this DTC
                continue;
            }

            DTC dtc = DTC.getDTC(DTCSystem.POWERTRAIN, dtc_code);
            if (dtc == null) {
                // Atlas doesn't know about this DTC
                continue;
            }

            int baseIndex = index / 8;
            int bitNumber = index - (baseIndex * 8);
            int checkDTCNumber = (baseIndex << 3) | (bitNumber & 0x7);
            long enabledOffset = dtc_enabled_offset + baseIndex;
            supportedDTCS.add(new SubaruDISupportedDTC(this, dtc, enabledOffset, checkDTCNumber, bitNumber));
        }

        // Sort by name
        return supportedDTCS.stream().sorted(Comparator.comparing(x -> x.getDTC().getName())).toList();
    }

    private TableFunction createFunction(Function function) {
        Program program = getProgram();

        long offset = function.getEntryPoint().getOffset();

        DecompInterface decomp = new DecompInterface();

        try {
            decomp.openProgram(program);
            decomp.toggleCCode(false);
            DecompileResults results = decomp.decompileFunction(function, 60, TaskMonitor.DUMMY);
            if (!results.decompileCompleted()) {
                throw new IllegalArgumentException(Long.toHexString(offset) + ":" +
                        " decompile incomplete (err=" + results.getErrorMessage() + ")");
            }

            HighFunction highFunction = results.getHighFunction();
            FunctionPrototype prototype = highFunction.getFunctionPrototype();

            // Qualify the function
            if (prototype.getNumParams() != 2 && prototype.getNumParams() != 3) {
                // Failed to qualify: table can't be 1D or 2D
                throw new IllegalArgumentException(Long.toHexString(offset) + ": " + prototype.getNumParams() + " arguments");
            }

            HighSymbol param_1 = prototype.getParam(0);
            if (!(param_1.getDataType() instanceof PointerDataType)) {
                // Failed to qualify: table functions always start with a pointer as their first argument (to the table struct)
                throw new IllegalArgumentException(Long.toHexString(offset) + ": param_1 is not a pointer");
            }

            if (highFunction.getGlobalSymbolMap().getSymbols().hasNext()) {
                // Table functions always seem to avoid any constants
                throw new IllegalArgumentException(Long.toHexString(offset) + ": references global symbol(s)");
            }

            decomp.closeProgram();

            return new SubaruDITableFunction(this, program, prototype, function.getEntryPoint());
        } finally {
            decomp.closeProgram();
        }
    }

    @Override
    public TableExecution inspectCode(long offset) throws IOException {
        Address address = getAddress(offset);

        Instruction instruction;

        Program program = getProgram();

        Disassembler disassembler = getDisassembler();
        instruction = disassembleOne(disassembler, address);

        if (instruction == null) {
            return null;
        } else if (!instruction.getMnemonicString().equals("mov")) {
            return null;
        }

        int type = instruction.getOperandType(0);
        if (type != OperandType.SCALAR) {
            return null;
        }

        long code = instruction.getAddress().getOffset();
        Address codeAddress = program.getAddressFactory().getDefaultAddressSpace().getAddressInThisSpaceOnly(code);
        Function function = findNextFunction(program, disassembler, codeAddress);
        if (function == null) {
            throw new IllegalArgumentException(Long.toHexString(offset) + ":" + " no function found");
        }

        Scalar scalar = instruction.getScalar(0);
        long data = scalar.getUnsignedValue();

        TableFunction tableFunction = createFunction(function);

        return new SubaruDITableExecution(tableFunction, data, offset);
    }

    @Override
    public List<TableExecution> getExecutions(ProgressListener listener) {
        int length = getCalibration().getLength();
        AtomicInteger completed = new AtomicInteger();

        try {
            return Jobs.parallelize(IntStream.range(0, length - 4).boxed().flatMap(offs -> {
                if (Thread.interrupted()) {
                    throw new RuntimeException(new InterruptedException());
                }

                int num = completed.incrementAndGet();
                if (num % 2048 == 0) {
                    listener.updateProgress("Searching for data references in " + getCalibration().getName()
                            + "...", (float)num /(float) length);
                }

                TableExecution execution;
                try {
                    byte[] bytes = getCalibration().read(offs, 2);
                    if (bytes[0] == 0x26 && bytes[1] == 0x06) {
                        execution = inspectCode(offs);
                    } else {
                        return Stream.empty();
                    }
                } catch (Exception e) {
                    Log.ui().log(Level.FINE, "Ignoring reference at " + offs, e);
                    execution = null;
                }

                if (execution != null && getCalibration().getSection().contains(execution.getDataOffset())) {
                    return Stream.of(execution);
                } else {
                    return Stream.empty();
                }
            }));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Function findNextFunction(Program program, Disassembler disassembler, Address address) {
        disassembler.resetDisassemblerContext();

        Instruction instruction;
        Address function = null;

        while (true) {
            instruction = disassembleOne(disassembler, address);
            if (instruction == null) break;

            if (instruction.getFlowType() == RefType.UNCONDITIONAL_CALL) {
                function = instruction.getFlows()[0];
                break;
            } else if (instruction.getFlowType() == RefType.UNCONDITIONAL_JUMP) {
                address = instruction.getFlows()[0];
                continue;
            }

            address = instruction.getDefaultFallThrough();
            if (address == null) {
                break;
            }
        }

        if (function == null) {
            return null;
        }

        return new UndefinedFunction(program, function);
    }

    @Override
    public TableComparer createComparer() {
        return new SubaruDITableComparer();
    }
}
