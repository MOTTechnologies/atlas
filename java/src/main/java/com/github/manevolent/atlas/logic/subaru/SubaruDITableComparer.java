package com.github.manevolent.atlas.logic.subaru;

import com.github.manevolent.atlas.checked.CheckedSupplier;
import com.github.manevolent.atlas.logic.AbstractGhidraOS;
import com.github.manevolent.atlas.logic.OS;
import com.github.manevolent.atlas.logic.TableComparer;
import com.github.manevolent.atlas.logic.TableExecution;
import com.github.manevolent.atlas.model.Calibration;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.listing.Instruction;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.github.manevolent.atlas.logic.AbstractGhidraOS.disassembleOne;

public class SubaruDITableComparer implements TableComparer {
    private Map<Long, List<Instruction>> instructionCache = new HashMap<>();

    public SubaruDITableComparer() {

    }


    @Override
    public float compareCode(TableExecution a, TableExecution b) throws IOException {
        if (a == null) {
            throw new NullPointerException("a");
        } else if (b == null) {
            throw new NullPointerException("b");
        }

        if (!(a instanceof SubaruDITableExecution a_subaru) || !(b instanceof SubaruDITableExecution b_subaru)) {
            throw new UnsupportedOperationException("must compare Subaru DI table executions");
        }

        return compare(a_subaru, b_subaru);
    }

    public float compare(SubaruDITableExecution a, SubaruDITableExecution b) throws IOException {
        if (!(a.getFunction().getOS() instanceof SubaruDIOS a_os)) {
            throw new UnsupportedOperationException("must compare two Subaru DI OS");
        }

        if (!(b.getFunction().getOS() instanceof SubaruDIOS b_os)) {
            throw new UnsupportedOperationException("must compare two Subaru DI OS");
        }

        List<Instruction> a_ins_list = readInstructionsCached(a_os.getDisassembler(), a_os, a.getMovLocation(),
                a.getFunction().getOffset());

        List<Instruction> b_ins_list = readInstructionsCached(b_os.getDisassembler(), b_os, b.getMovLocation(),
                b.getFunction().getOffset());

        int length = Math.max(a_ins_list.size(), b_ins_list.size());

        if (length < 8) {
            throw new IllegalStateException("not enough instructions to compare");
        }

        float sum = 0f;
        for (int i = 0; i < length; i ++) {
            Instruction a_ins = i < a_ins_list.size() ? a_ins_list.get(i) : null;
            Instruction b_ins = i < b_ins_list.size() ? b_ins_list.get(i) : null;

            if (a_ins == null || b_ins == null) {
                continue;
            }

            if (a_ins.getMnemonicString().equals(b_ins.getMnemonicString())) {
                sum ++;
            }
        }

        if (length == 0) {
            return 0f;
        }

        return sum / length;
    }

    private List<Instruction> readInstructionsCached(Disassembler disassembler, SubaruDIOS os, long entrypoint,
                                                     long tableFunction) {
        if (instructionCache.containsKey(entrypoint)) {
            return instructionCache.get(entrypoint);
        } else {
            List<Instruction> instructions = readInstructions(disassembler, os, entrypoint, tableFunction);
            instructionCache.put(entrypoint, instructions);
            return instructions;
        }
    }

    private List<Instruction> readInstructions(Disassembler disassembler, SubaruDIOS os, long entrypoint,
                                               long tableFunction) {
        long offs = entrypoint;
        Instruction instruction;
        List<Instruction> instructions = new ArrayList<>();

        while (true) {
            instruction = disassembleOne(disassembler, os.getAddress(offs));

            if (instruction == null) {
                break;
            }

            instructions.add(instruction);

            offs += instruction.getLength();

            if (!instruction.isFallthrough()) {
                if (instruction.getFlows().length == 1 && instruction.getFlows()[0].getOffset() == tableFunction) {
                    continue;
                }

                if (instruction.getMnemonicString().equals("jmp") || instruction.getMnemonicString().equals("dispose")) {
                    break;
                }
            }
        }

        return instructions;
    }

    @Deprecated
    private static float scoreTableCodeMatch(Calibration sourceCalibration,
                                             TableExecution sourceExecution,
                                             Calibration targetCalibration,
                                             TableExecution targetExecution) throws IOException {
        int size = 200;

        byte[] sourceCode = new byte[size];
        sourceCalibration.read(sourceCode, sourceExecution.getFunction().getOffset(), 0, size);

        byte[] targetCode = new byte[size];
        targetCalibration.read(targetCode, targetExecution.getFunction().getOffset(), 0, size);

        float total = 0f;
        float sum = 0f;
        for (int i = 0; i < size; i ++) {
            float factor = 1f - ((float)i / (float)size);

            int s = sourceCode[i];
            int t = targetCode[i];

            for (int b = 0; b < 8; b ++) {
                int b_s = (s >> b) & 0x1;
                int b_t = (t >> b) & 0x1;

                if (b_s == b_t) {
                    sum += (factor / 8f);
                }
            }

            total += factor;
        }

        return sum / total;
    }

}
